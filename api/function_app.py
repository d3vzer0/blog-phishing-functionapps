# Example Function app containing two
# functions to fetch brand/logo information via either
# Google's Vision API or Azure Cognitive Services
# DONT USE IN PRODUCTION!

import json
import logging
import os
import azure.functions as func
import io
from playwright.async_api import async_playwright
from google.cloud import vision
from google.oauth2 import service_account
from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from azure.cognitiveservices.vision.computervision.models import \
    VisualFeatureTypes
from msrest.authentication import CognitiveServicesCredentials
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


# Intialise app and set auth_level to anonymous access
# since authoriziation will be done by integrating with Azure AD
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


# Custom config for vision acess
# and to hide that we're using a headless browser
CONF = {
    'key_vault': os.getenv('KEY_VAULT_URI'),
    'user_agent': os.getenv('HEADER_UA', 'Mozilla/5.0 (Windows NT 10.0; Windows; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36'),
    'extra_http_headers': {
        'accept': os.getenv('HEADER_ACCEPT', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'),
        'encoding': os.getenv('HEADER_ENC', 'gzip, deflate'),
        'lang': os.getenv('HEADER_LANG', 'en-GB,en-US;q=0.9,en;q=0.8')
    },
    'gcloud_static': {
        'type': 'service_account',
        'universe_domain': 'googleapis.com',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
    },
    'gcloud_vault': {
        'project_id': 'g-project-id',
        'private_key_id': 'g-private-key-id',
        'private_key': 'g-pkey',
        'client_email': 'g-client-email',
        'client_id': 'g-client-id',
        'client_x509_cert_url': 'g-cert-url'
    },
    'azure_vault': {
        'key': 'az-key',
        'endpoint': 'az-endpoint'
    }
}


async def get_screenshot(uri: str) -> bytes:
    """ Function to create a screenshot of target uri

    Args:
        uri (str): Uri to create screenshots of

    Returns:
        bytes: Bytes containing the screenshot (as png)
    """
    async with async_playwright() as session:
        # Create a new session with chromium
        browser_type = session.chromium
        browser = await browser_type.launch()

        # Open a newp age with our custom headers
        page = await browser.new_page(user_agent=CONF['user_agent'],
                                      extra_http_headers=CONF['extra_http_headers'])

        # Go to uri and create screenshot
        await page.goto(uri)
        screenshot = await page.screenshot()

        # Close the browser
        await browser.close()
        return screenshot


@app.function_name(name="GCloudSnapshot")
@app.route(route="gcloud", methods=['GET'])
async def gcloud_snapshot(req: func.HttpRequest) -> func.HttpResponse:
    """ Gets the URI param, creates screenshot and calls the Google Vision API
    to retrieve a list of identified brands

    Args:
        req (func.HttpRequest): HTTP request handler

    Returns:
        func.HttpResponse: API request response
    """

    # Get target URI from request parameters
    target_uri = req.params.get('uri')
    if not target_uri:
        return func.HttpResponse(
            json.dumps({"message":"Missing uri parameter in request"}),
            mimetype='application/json',
            status_code=400
        )
    logging.info(f"action=request, uri={target_uri}")

    # Authenticate Azure Key vault and get secrets
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=CONF['key_vault'], credential=credential)
    gcloud_vault_settings = {}
    for key, target in CONF['gcloud_vault'].items():
        get_secret = secret_client.get_secret(target)
        gcloud_vault_settings[key] = get_secret.value.replace('\\n', '\n')

    # Authenticate with Google Cloud
    credentials = service_account.Credentials.from_service_account_info({**CONF['gcloud_static'], **gcloud_vault_settings})
    
    # Create screenshot
    screenshot = await get_screenshot(target_uri)
    # screenshot_object = io.BytesIO(screenshot)
    logging.info(f"action=screenshot, uri={target_uri}")

    # Initialise computer vision client
    client = vision.ImageAnnotatorClient(credentials=credentials)
    image = vision.Image(content=screenshot)

    # Detect logos
    response = client.logo_detection(image=image)
    brands = [{'name': brand.description, 'confidence': brand.score} for brand in response.logo_annotations]
    logging.info(f"action=analyze, uri={target_uri}, results='{json.dumps(brands)}'")

    # # Return the results as json
    return func.HttpResponse(json.dumps(brands), mimetype='application/json')


@app.function_name(name="AzureSnapshot")
@app.route(route="azure", methods=['GET'])
async def azure_napshot(req: func.HttpRequest) -> func.HttpResponse:
    """ Gets the URI param, creates screenshot and calls the Azure Cognitive
    services API to retrieve a list of identified logos

    Args:
        req (func.HttpRequest): HTTP request handler

    Returns:
        func.HttpResponse: API request response
    """

    # Get target URI from request parameters
    target_uri = req.params.get('uri')
    if not target_uri:
        return func.HttpResponse(
            json.dumps({"message":"Missing uri parameter in request"}),
            mimetype='application/json',
            status_code=400
        )
    logging.info(f"action=request, uri={target_uri}")

    # Authenticate Azure Key vault and get secrets
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=CONF['key_vault'], credential=credential)

    # Initialise computer vision client
    endpoint = secret_client.get_secret(CONF['azure_vault']['endpoint'])
    api_key = secret_client.get_secret(CONF['azure_vault']['key'])
    client = ComputerVisionClient(
        endpoint.value,
        CognitiveServicesCredentials(api_key.value)
    )

    # Create screenshot
    screenshot = await get_screenshot(target_uri)

    screenshot_object = io.BytesIO(screenshot)
    logging.info(f"action=screenshot, uri={target_uri}")

    # Analyze image and create a list with the results
    image_analysis = client.analyze_image_in_stream(screenshot_object,
            visual_features=[VisualFeatureTypes.brands])

    brands = [{'name': brand.name, 'confidence': brand.confidence} for brand in image_analysis.brands]
    logging.info(f"action=analyze, uri={target_uri}, results='{json.dumps(brands)}'")

    # Return the results as json
    return func.HttpResponse(json.dumps(brands), mimetype='application/json')

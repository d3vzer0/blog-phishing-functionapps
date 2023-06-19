## Thanks to https://github.com/Azure/azure-functions-python-worker/issues/915 ( evanlouie )
FUNC_VERSION = $(shell func --version)
FUNC_PATH = $(shell realpath $$(which func))
FUNC_OSX_WORKER_PATH = $(dir $(FUNC_PATH))workers/python/3.10/OSX
FUNC_WORKER_CONFIG_JSON = $(dir $(FUNC_PATH))workers/python/worker.config.json
FUNC_OSX_WORKER_X64 = $(FUNC_OSX_WORKER_PATH)/X64
FUNC_OSX_WORKER_ARM64 = $(FUNC_OSX_WORKER_PATH)/Arm64
.PHONY: $(FUNC_OSX_WORKER_ARM64)
$(FUNC_OSX_WORKER_ARM64):
	cp -r $(FUNC_OSX_WORKER_PATH)/X64 $(FUNC_OSX_WORKER_PATH)/Arm64
	pip install grpcio --upgrade --target $@

.PHONY: $(FUNC_WORKER_CONFIG_JSON)
$(FUNC_WORKER_CONFIG_JSON): 
	cp $(FUNC_WORKER_CONFIG_JSON) $(FUNC_WORKER_CONFIG_JSON).bak
	cat $(FUNC_WORKER_CONFIG_JSON) \
		| jq '.description.supportedArchitectures |= .+ ["Arm64"]' \
		> $(FUNC_WORKER_CONFIG_JSON).tmp
	mv $(FUNC_WORKER_CONFIG_JSON).tmp $(FUNC_WORKER_CONFIG_JSON)

.PHONY: install_func_arm64_worker
install_func_arm64_worker: $(FUNC_OSX_WORKER_ARM64) $(FUNC_WORKER_CONFIG_JSON)

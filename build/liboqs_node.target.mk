# This file is generated by gyp; do not edit.

TOOLSET := target
TARGET := liboqs_node
### Rules for action "prebuild":
quiet_cmd_binding_gyp_liboqs_node_target_prebuild = ACTION Executing prebuild script $@
cmd_binding_gyp_liboqs_node_target_prebuild = LD_LIBRARY_PATH=$(builddir)/lib.host:$(builddir)/lib.target:$$LD_LIBRARY_PATH; export LD_LIBRARY_PATH; cd $(srcdir)/.; npm run prebuild

.: obj := $(abs_obj)
.: builddir := $(abs_builddir)
.: TOOLSET := $(TOOLSET)
.:  FORCE_DO_CMD
	$(call do_cmd,binding_gyp_liboqs_node_target_prebuild)

all_deps += .
action_binding_gyp_liboqs_node_target_prebuild_outputs := .


DEFS_Debug := \
	'-DNODE_GYP_MODULE_NAME=liboqs_node' \
	'-DUSING_UV_SHARED=1' \
	'-DUSING_V8_SHARED=1' \
	'-DV8_DEPRECATION_WARNINGS=1' \
	'-D_GLIBCXX_USE_CXX11_ABI=1' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-D__STDC_FORMAT_MACROS' \
	'-DOPENSSL_NO_PINSHARED' \
	'-DOPENSSL_THREADS' \
	'-DNAPI_CPP_EXCEPTIONS' \
	'-DNAPI_VERSION=6' \
	'-DNODE_API_NO_EXTERNAL_BUFFERS_ALLOWED' \
	'-DBUILDING_NODE_EXTENSION' \
	'-DDEBUG' \
	'-D_DEBUG'

# Flags passed to all source files.
CFLAGS_Debug := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-fexceptions \
	-std=c++2a \
	-m64 \
	-g \
	-O0

# Flags passed to only C files.
CFLAGS_C_Debug :=

# Flags passed to only C++ files.
CFLAGS_CC_Debug := \
	-fno-rtti \
	-fno-exceptions \
	-fno-strict-aliasing \
	-std=gnu++17 \
	-fexceptions \
	-std=c++2a

INCS_Debug := \
	-I/home/sneh/.cache/node-gyp/22.13.0/include/node \
	-I/home/sneh/.cache/node-gyp/22.13.0/src \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/openssl/config \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/openssl/openssl/include \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/uv/include \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/zlib \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/v8/include \
	-I/home/sneh/Desktop/TeleAI/liboqs/liboqs-node/node_modules/node-addon-api \
	-I$(srcdir)/deps/liboqs/build/include \
	-I$(srcdir)/deps/liboqs-cpp/include

DEFS_Release := \
	'-DNODE_GYP_MODULE_NAME=liboqs_node' \
	'-DUSING_UV_SHARED=1' \
	'-DUSING_V8_SHARED=1' \
	'-DV8_DEPRECATION_WARNINGS=1' \
	'-D_GLIBCXX_USE_CXX11_ABI=1' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-D__STDC_FORMAT_MACROS' \
	'-DOPENSSL_NO_PINSHARED' \
	'-DOPENSSL_THREADS' \
	'-DNAPI_CPP_EXCEPTIONS' \
	'-DNAPI_VERSION=6' \
	'-DNODE_API_NO_EXTERNAL_BUFFERS_ALLOWED' \
	'-DBUILDING_NODE_EXTENSION'

# Flags passed to all source files.
CFLAGS_Release := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-fexceptions \
	-std=c++2a \
	-m64 \
	-O3 \
	-fno-omit-frame-pointer

# Flags passed to only C files.
CFLAGS_C_Release :=

# Flags passed to only C++ files.
CFLAGS_CC_Release := \
	-fno-rtti \
	-fno-exceptions \
	-fno-strict-aliasing \
	-std=gnu++17 \
	-fexceptions \
	-std=c++2a

INCS_Release := \
	-I/home/sneh/.cache/node-gyp/22.13.0/include/node \
	-I/home/sneh/.cache/node-gyp/22.13.0/src \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/openssl/config \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/openssl/openssl/include \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/uv/include \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/zlib \
	-I/home/sneh/.cache/node-gyp/22.13.0/deps/v8/include \
	-I/home/sneh/Desktop/TeleAI/liboqs/liboqs-node/node_modules/node-addon-api \
	-I$(srcdir)/deps/liboqs/build/include \
	-I$(srcdir)/deps/liboqs-cpp/include

OBJS := \
	$(obj).target/$(TARGET)/src/addon.o \
	$(obj).target/$(TARGET)/src/KEMs.o \
	$(obj).target/$(TARGET)/src/KeyEncapsulation.o \
	$(obj).target/$(TARGET)/src/Random.o \
	$(obj).target/$(TARGET)/src/Signature.o \
	$(obj).target/$(TARGET)/src/Sigs.o

# Add to the list of files we specially track dependencies for.
all_deps += $(OBJS)

# Make sure our actions/rules run before any of us.
$(OBJS): | $(action_binding_gyp_liboqs_node_target_prebuild_outputs)

# CFLAGS et al overrides must be target-local.
# See "Target-specific Variable Values" in the GNU Make manual.
$(OBJS): TOOLSET := $(TOOLSET)
$(OBJS): GYP_CFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_C_$(BUILDTYPE))
$(OBJS): GYP_CXXFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_CC_$(BUILDTYPE))

# Suffix rules, putting all outputs into $(obj).

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(srcdir)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# Try building from generated source, too.

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj).$(TOOLSET)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# End of this set of suffix rules
### Rules for final target.
# Build our special outputs first.
$(obj).target/oqs_node.node: | $(action_binding_gyp_liboqs_node_target_prebuild_outputs)

# Preserve order dependency of special output on deps.
$(action_binding_gyp_liboqs_node_target_prebuild_outputs): | 

LDFLAGS_Debug := \
	-pthread \
	-rdynamic \
	-m64

LDFLAGS_Release := \
	-pthread \
	-rdynamic \
	-m64

LIBS := \
	../deps/liboqs/build/lib/liboqs.a \
	-lcrypto \
	-lssl

$(obj).target/oqs_node.node: GYP_LDFLAGS := $(LDFLAGS_$(BUILDTYPE))
$(obj).target/oqs_node.node: LIBS := $(LIBS)
$(obj).target/oqs_node.node: TOOLSET := $(TOOLSET)
$(obj).target/oqs_node.node: $(OBJS) FORCE_DO_CMD
	$(call do_cmd,solink_module)

all_deps += $(obj).target/oqs_node.node
# Add target alias
.PHONY: liboqs_node
liboqs_node: $(builddir)/oqs_node.node

# Copy this to the executable output path.
$(builddir)/oqs_node.node: TOOLSET := $(TOOLSET)
$(builddir)/oqs_node.node: $(obj).target/oqs_node.node FORCE_DO_CMD
	$(call do_cmd,copy)

all_deps += $(builddir)/oqs_node.node
# Short alias for building this executable.
.PHONY: oqs_node.node
oqs_node.node: $(obj).target/oqs_node.node $(builddir)/oqs_node.node

# Add executable to "all" target.
.PHONY: all
all: $(builddir)/oqs_node.node


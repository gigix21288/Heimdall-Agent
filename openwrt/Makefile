# OpenWrt package for the Heimdall Agent.
#
# EXPERIMENTAL / ADVANCED. Building this needs the OpenWrt SDK, and scapy +
# python3 are heavy for many home routers (flash/RAM). For most users the
# Docker or Raspberry Pi route is recommended — see the main README.
#
# Build (inside an OpenWrt SDK tree):
#   1) cp ../heimdall_agent.py ./files/heimdall_agent.py
#   2) place this folder under package/heimdall-agent/
#   3) make package/heimdall-agent/compile V=s
#
include $(TOPDIR)/rules.mk

PKG_NAME:=heimdall-agent
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/heimdall-agent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Heimdall Agent (LAN sensor for the Heimdall app)
  URL:=https://github.com/gigix21288/Heimdall-Agent
  DEPENDS:=+python3-light +python3-asyncio +python3-logging +libpcap
endef

define Package/heimdall-agent/description
  Streams LAN packet headers to the Heimdall OS phone app over a local
  WebSocket. Requires python3-scapy and python3-websockets to be installed via
  pip on the device (not in the OpenWrt feeds). Experimental.
endef

define Build/Compile
endef

define Package/heimdall-agent/install
	$(INSTALL_DIR) $(1)/opt/heimdall-agent
	$(INSTALL_BIN) ./files/heimdall_agent.py $(1)/opt/heimdall-agent/heimdall_agent.py
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/heimdall-agent.init $(1)/etc/init.d/heimdall-agent
endef

$(eval $(call BuildPackage,heimdall-agent))

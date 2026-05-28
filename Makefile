TARGET := iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyDebugTool

MyDebugTool_FILES = Tweak.x
MyDebugTool_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/tweak.mk

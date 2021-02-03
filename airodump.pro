TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lncurses
LIBS += -pthread
SOURCES += \
        main.cpp

HEADERS += \
    netformat.h

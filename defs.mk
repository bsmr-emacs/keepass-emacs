OBJS=		dllmain.obj keepass.obj AssemblyInfo.obj
NAME=		keepassdll
DEFS=		
LIBS=		$(LIBS) user32.lib ole32.lib Oleaut32.lib Ws2_32.lib imm32.lib
DEBUG=		DBG
LINKFLAGS=	-nologo -DLL -manifest -incremental:no

!ifdef DEBUG
DBG_FLAG=	-Zi
LDBG_FLAG=	/debug /assemblydebug 
DEBUG=		DBG
!else
DBG_FLAG=
LDBG_FLAG=
!endif
KEEPASSDIR=c:/Program Files (x86)/KeePass Password Safe 2

COMMON_CXXCLAGS=\
	-nologo -MD  $(DEFS) $(DBG_FLAG) $(OPT_FLAG) \
	/FD /EHa /clr /Fp"KeePass_$(DEBUG).pch" \
	/FU "c:\Windows\Microsoft.NET\Framework\v2.0.50727\System.dll" \
	/FU "c:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Data.dll" \
	/FU "c:\Windows\Microsoft.NET\Framework\v2.0.50727\System.XML.dll" \
	/FU "c:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Drawing.dll" \
	/FU "c:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Windows.Forms.dll"

CPPFLAGS=  /Yc"stdafx.h" $(COMMON_CXXCLAGS)
CXXFLAGS=  /AI"$(KEEPASSDIR)" /Yu"stdafx.h" $(COMMON_CXXCLAGS)

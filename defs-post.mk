MKFILES=defs.mk defs-post.mk
dllmain.obj: dllmain.c keepass.h $(MKFILES)
keepass.obj: keepass.cxx keepass.h KeePass_$(DEBUG).pch  $(MKFILES)
AssemblyInfo.obj: stdafx.h $(MKFILES)
KeePass_$(DEBUG).pch: AssemblyInfo.obj  $(MKFILES)

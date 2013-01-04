/*
emacs-Keepass: Copyright (c) 2012 HIROSHI OOTA.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef NULL
#undef NULL
#endif

#include <config.h>
#include <setjmp.h>
#ifdef _WIN32
#define extern __declspec(dllimport) extern
#endif
#include <lisp.h>

/* coding.h */
extern Lisp_Object code_convert_string_norecord P_ ((Lisp_Object, Lisp_Object,
						     int));
extern Lisp_Object Qutf_16, Vlocale_coding_system;
#undef extern

#include <dynload.h>
#pragma warning(error : 4013)

#ifndef WINDOWSNT
#define INVALID_HANDLE_VALUE NULL
#include <dlfcn.h>
#endif

#include <windows.h>
#include <objbase.h>
#include <assert.h>

#define DECODE_SYSTEM(str)						   \
  (! NILP (Vlocale_coding_system)					   \
   && !EQ (Vlocale_coding_system, make_number (0))			   \
   ? code_convert_string_norecord (str, Vlocale_coding_system, 0)	   \
   : str)

Lisp_Object Qkeepass_group, Qkeepass_entry;
static Lisp_Object Vdefault_visible_fields, 
    Vuuid_regex, Vsupported_mech_alist,
    Vpipe , Vre_head, Vre_tail;

#include "keepass.h"


/*
 * keepass object
 */ 
struct keepass_object
{
    struct vectorlike_header header;
    Lisp_Object type;
    Lisp_Object visible_fields;
    void (*finalizer)(struct Lisp_Vector *);
    void *kp_obj; /* System::Runtime::InteropServices::GCHandle::ToIntPtr
		  (System::Runtime::InteropServices::GCHandle) */
};

static void keepass_db_finalizer(struct Lisp_Vector *v)
{
    struct keepass_object *kp_obj =
	(struct keepass_object *)v;
    Lisp_Object o;

    if (kp_obj->kp_obj) {
	if (EQ(kp_obj->type, Qkeepass_group))
	  free_group(kp_obj->kp_obj);
	else if (EQ(kp_obj->type, Qkeepass_entry))
	  free_entry(kp_obj->kp_obj);
	else
	  assert(0 != 0);
	kp_obj->kp_obj = NULL;
    }

    finalize_pseudovector(v);
}

static struct keepass_object *
allocate_keepass_object (Lisp_Object type, Lisp_Object vis_fld)
{
  struct keepass_object *kp_obj =
      ALLOCATE_PSEUDOVECTOR (struct keepass_object,
			     finalizer, PVEC_GENERIC);

  kp_obj->type = type;
  kp_obj->visible_fields = vis_fld;
  kp_obj->finalizer = keepass_db_finalizer;
  kp_obj->kp_obj = NULL;
  return kp_obj;
}

#define CHECK_KEEPASS_OBJ(x,t) \
    CHECK_TYPE(is_valid_keepass_obj(x, t), t, x)

#define CHECK_GROUP_OBJ(x) CHECK_KEEPASS_OBJ(x, Qkeepass_group)
#define CHECK_ENTRY_OBJ(x) CHECK_KEEPASS_OBJ(x, Qkeepass_entry)

static int is_valid_keepass_obj(Lisp_Object obj, Lisp_Object sym)
{
    struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(obj);

    return 
	GENERICP(obj)
	&& EQ(kp_obj->type, sym)
	&& kp_obj->kp_obj != NULL;
}

static Lisp_Object error_handler(Lisp_Object arg)
{
    return Qnil;
}

DEFUN("keepass-open", Fkeepass_open, Skeepass_open, 2, 3, 0,
      doc:/*open an KeePass database file as specified by the FILENAME argument.
AUTHPARAM is authentication paramater,
string: it will be treated as password, keyfile will not be used.
symbol or cons whos car is lambda: function for password query.
it should return (password keyfile . useraccount).
if useraccount is non nil, the current user account credentials will be used.
the function returns nil, keepass-open function will be canceled.
cons: (password keyfile . useraccount)
nil: KeePass will query authentication paramater.

optional third argument VISIBLE-FIELDS is a list of visible field's name. 
if VISIBLE-FIELDS is nil, "Title", "UserName", "URL" and "Notes" are visible.
field names are case insentitive.*/)
     (filename, authparam, visible_fields)
     Lisp_Object filename;
     Lisp_Object authparam;
     Lisp_Object visible_fields;
{
    Lisp_Object obj = Qnil;
    struct keepass_object * o;
    void *db;
    char *errstr;
    Lisp_Object password, keyfile, useraccount;
    struct gcpro gcpro1, gcpro2, gcpro3, gcpro4;
    
    GCPRO3 (filename, authparam, visible_fields);

    CHECK_STRING(filename);
    if (!NILP(visible_fields))
      CHECK_CONS(visible_fields);
    else 
      visible_fields = Vdefault_visible_fields;

    visible_fields
	= Fmapconcat(intern("concat"), 
		     visible_fields, Vpipe);

    {
	Lisp_Object a[] = {Vre_head, visible_fields, Vre_tail};
	visible_fields
	    = Fconcat(sizeof(a) / sizeof(a[0]), a);
    }
    
    filename = Fexpand_file_name(filename, Qnil);

    if (!NILP(authparam) && !EQ(authparam, Qt)) {
	if (STRINGP(authparam)) {
	    password = authparam;
	    keyfile = useraccount = Qnil;
	} else {
	    CHECK_CONS(authparam);
	    if (EQ(XCAR(authparam), Qlambda)) {
		authparam =
		    internal_condition_case_2
		    (Ffuncall, 1, &authparam,  Qt, error_handler);
		if (NILP(authparam))
		  return Qnil;
		CHECK_CONS(authparam);
	    } 
	    if (XINT(Flength(authparam)) != 3)
	      error("authparam requires three elements");
	    password = XCAR(authparam);
	    keyfile = XCAR(XCDR(authparam));
	    useraccount = XCDR(XCDR(authparam));
	}
	CHECK_TYPE(NILP(password) || STRINGP(password), Qstringp, password);
	CHECK_TYPE(NILP(keyfile) || STRINGP(keyfile), Qstringp, keyfile);
	CHECK_TYPE(NILP(useraccount) || STRINGP(useraccount),
		   Qstringp, useraccount);
	if (!NILP(keyfile)) { 
	    CHECK_STRING(keyfile);
	    keyfile = Fexpand_file_name (keyfile, Qnil);
	}
    
	if ((db = open_database
	     (SDATA(filename), 
	      NILP(password) ? NULL : SDATA(password),
	      NILP(keyfile) ? NULL : SDATA(keyfile),
	      !NILP(useraccount),
	      &errstr)) == NULL) {
	    struct gcpro gcpro1;
	    Lisp_Object err = Qnil;
	    GCPRO1(err);
	    err = build_string(errstr);
	    error(SDATA(DECODE_SYSTEM(err)));
	}
    } else {
	if ((db = open_database_dlg(
		 SDATA(filename), !NILP(authparam), &errstr)) == NULL) {
	    if (errstr != NULL) {
		struct gcpro gcpro1;
		Lisp_Object err = Qnil;
		GCPRO1(err);
		err = build_string(errstr);
		error(SDATA(DECODE_SYSTEM(err)));
		/* never reached */
	    }
	    return Qnil; /* canceled */
	}
    }

    o = allocate_keepass_object(Qkeepass_group, 
				NILP(visible_fields)
				? Vdefault_visible_fields
				: visible_fields);
    o->kp_obj = db;
    XSETPSEUDOVECTOR (obj, o, PVEC_GENERIC);
    return obj;
}

DEFUN("keepass-group-parent", 
      Fkeepass_group_parent, Skeepass_group_parent, 1, 1, 0,
      doc:/* Get parent of GROUP object*/)
     (group)
     Lisp_Object group;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(group);
     void *parent;
     Lisp_Object obj;
     struct keepass_object * o;

     CHECK_KEEPASS_OBJ(group, Qkeepass_group);

     parent = get_group_parent(kp_obj->kp_obj);
     if (parent == NULL)
       return Qnil;
     o = allocate_keepass_object(Qkeepass_group, kp_obj->visible_fields);
     o->kp_obj = parent;
     XSETPSEUDOVECTOR (obj, o, PVEC_GENERIC);

     return obj;
}

DEFUN("keepass-group-uuid", 
      Fkeepass_group_uuid, Skeepass_group_uuid, 1, 1, 0,
      doc:/* Get uuid of GROUP object*/)
     (group)
     Lisp_Object group;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(group);
     char *uuid;
     Lisp_Object obj;
       
     CHECK_KEEPASS_OBJ(group, Qkeepass_group);

     uuid = get_group_uuid(kp_obj->kp_obj, xmalloc);
     obj = build_string(uuid);
     xfree(uuid);
     return obj;
}

DEFUN("keepass-group-name", 
      Fkeepass_group_name, Skeepass_group_name, 1, 1, 0,
      doc:/* Get name of GROUP object*/)
     (group)
     Lisp_Object group;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(group);
     char *name;
     Lisp_Object obj;
       
     CHECK_KEEPASS_OBJ(group, Qkeepass_group);

     name = get_group_name(kp_obj->kp_obj, xmalloc);
     obj = build_string(name);
     xfree(name);
     return obj;
}

DEFUN("keepass-group-fullpath", 
      Fkeepass_group_fullpath, Skeepass_group_fullpath, 1, 2, 0,
      doc:/* Get fullapth of GROUP object. 
	     SEPARATOR should be string or nil(default \"/\").*/)
(group, separator)
     Lisp_Object group;
     Lisp_Object separator;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(group);
     char *path;
     Lisp_Object obj;
       
     CHECK_KEEPASS_OBJ(group, Qkeepass_group);
     path = get_group_fullpath(kp_obj->kp_obj, 
			       NILP(separator)
			       ? "/"
			       : SDATA(separator),
			       xmalloc);
     obj = build_string(path);
     xfree(path);
     return obj;
}

static int gnamecmp(struct keepass_object *kp_obj,
		    Lisp_Object name, int err)
{
    int v;
    char *gname;
    Lisp_Object obj;
       
    CHECK_STRING(name);
    gname = get_group_name(kp_obj->kp_obj, xmalloc);
    
    v = stricmp(SDATA(name), gname);
    if (err && v) {
	char *gg = alloca(strlen(gname) + 1);
	strcpy(gg, gname);
	xfree(gname);
	error("%s != %s", gg, SDATA(name));
    }
    xfree(gname);
    return v;
}

DEFUN("keepass-group-entry",
      Fkeepass_group_entry, Skeepass_group_entry, 2, 2, 0,
      doc:/* find a entry which is specified by ENTRY-SPEC from GROUP object.
	     ENTRY-SPEC is uuid or entry-spec which is parsed by keepass-parse-entry-spec.*/)
(group, entry_spec)
     Lisp_Object group;
     Lisp_Object entry_spec;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(group);
     void *g_obj, *e_obj;
     Lisp_Object e_spec, g_spec;
     
     CHECK_KEEPASS_OBJ(group, Qkeepass_group);
     if (STRINGP(entry_spec)) {
	 if (NILP(Fstring_match(Vuuid_regex, entry_spec, Qnil)))
	   error("%s: UUID format is invalid", entry_spec);
	 g_obj = NULL;
	 e_obj = find_group_entry_by_uuid(kp_obj->kp_obj, SDATA(entry_spec));
     } else {
	 unsigned char **attrs;
	 int i;

	 CHECK_CONS(entry_spec);
	 attrs = alloca(sizeof(char *)
			* (XINT(Flength(entry_spec)) * 2 + 1));

	 for (e_spec = XCAR(entry_spec);
	      !NILP(e_spec); e_spec = XCDR(e_spec)) {
	     CHECK_STRING(XCAR(XCAR(e_spec))); /* key */
	     CHECK_STRING(XCDR(XCAR(e_spec))); /* value */
	 }
	 
	 for (g_spec = XCDR(entry_spec); !NILP(g_spec); g_spec = XCDR(g_spec))
	   CHECK_STRING(XCAR(g_spec));
	 g_spec = XCDR(entry_spec);
	 
	 gnamecmp(kp_obj, XCAR(g_spec), 1);
	 g_obj = kp_obj->kp_obj;
	 
	 for (g_spec = XCDR(g_spec); /* skip root */
	      !NILP(g_spec); g_spec = XCDR(g_spec)) {
	     void *g = find_group_child(g_obj, SDATA(XCAR(g_spec)));

	     if (g_obj != kp_obj->kp_obj)
	       free_group(g_obj);
	     g_obj = g;
	     
	     if (g_obj == NULL)
	       return Qnil;
	 }
	 for (i = 0, e_spec = XCAR(entry_spec);
	      !NILP(e_spec); e_spec = XCDR(e_spec)) {
	     attrs[i++] = SDATA(XCAR(XCAR(e_spec)));
	     attrs[i++] = SDATA(XCDR(XCAR(e_spec)));
	 }
	 attrs[i++] = NULL;
	 e_obj = find_group_entry(g_obj, attrs);
	 free_group(g_obj);
	 g_obj = NULL;
     }
     if (e_obj == NULL)
       return Qnil;

     {
	 struct keepass_object * e =
	     allocate_keepass_object(Qkeepass_entry, kp_obj->visible_fields);
	 Lisp_Object obj;
	 e->kp_obj = e_obj;
	 XSETPSEUDOVECTOR (obj, e, PVEC_GENERIC);
	 return obj;
     }
}

DEFUN("keepass-entry-parent", 
      Fkeepass_entry_parent, Skeepass_entry_parent, 1, 1, 0,
      doc:/* Get parent of ENTRY object*/)
     (entry)
     Lisp_Object entry;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(entry);
     void *parent;
     Lisp_Object obj;
     struct keepass_object * o;

     CHECK_KEEPASS_OBJ(entry, Qkeepass_entry);

     parent = get_entry_parent(kp_obj->kp_obj);
     if (parent == NULL)
       return Qnil;
     o = allocate_keepass_object(Qkeepass_group, kp_obj->visible_fields);
     o->kp_obj = parent;
     XSETPSEUDOVECTOR (obj, o, PVEC_GENERIC);

     return obj;
}

DEFUN("keepass-entry-uuid", 
      Fkeepass_entry_uuid, Skeepass_entry_uuid, 1, 1, 0,
      doc:/* Get uuid of ENTRY object*/)
     (entry)
     Lisp_Object entry;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(entry);
     char *name;
     Lisp_Object obj;
       
     CHECK_KEEPASS_OBJ(entry, Qkeepass_entry);

     name = get_entry_uuid(kp_obj->kp_obj, xmalloc);
     obj = build_string(name);
     xfree(name);
     return obj;
}

DEFUN("keepass-entry-field", 
      Fkeepass_entry_field, Skeepass_entry_field, 2, 3, 0,
      doc:/* Retrieve the FILELD value of ENRTY object. 
if optional BINARYP is non nil, the function retrives binary field,
otherwise string field.*/)
(entry, field, binaryp)
Lisp_Object entry;
Lisp_Object field;
Lisp_Object binaryp;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(entry);
     char *fld;
     Lisp_Object obj;
     size_t allocated;

     CHECK_KEEPASS_OBJ(entry, Qkeepass_entry);
     if (!NILP(field))
       CHECK_STRING(field);
     fld = get_entry_field(kp_obj->kp_obj, 
			   NILP(field) ? NULL : SDATA(field),
			   SDATA(kp_obj->visible_fields),
			   !NILP(binaryp), &allocated, xmalloc);
     if (fld == NULL)
       return Qnil;
     obj = make_unibyte_string(fld, allocated);
     xfree(fld);
     return obj;
}

DEFUN("keepass-entry-hmac", 
      Fkeepass_entry_hmac, Skeepass_entry_hmac, 4, 4, 0,
      doc:/* computes the message authentication code for DATA
using the hash function MECHANISM and the password which is stored in ENTRY as key.
PASSWORD-FIELD is the field name of key for HMAC. if PASSWORD-FIELD is nil,
\"Password\" would be used.
MECHA is one of 'md5, 'ripemd160, 'sha1, 'sha256, 'sha384 or 'sha512.*/)
(entry, password_field, mechanism, data)
Lisp_Object entry;
Lisp_Object password_field;
Lisp_Object mechanism;
Lisp_Object data;
{
     struct keepass_object *kp_obj =
	(struct keepass_object *)XPNTR(entry);
     char *p;
     size_t allocated;
     Lisp_Object obj;

     if (!NILP(password_field))
       CHECK_STRING(password_field);
     CHECK_KEEPASS_OBJ(entry, Qkeepass_entry);
     CHECK_STRING(data);
     CHECK_SYMBOL(mechanism);

     mechanism = Fassq(mechanism, Vsupported_mech_alist);
     if (NILP(mechanism))
       error("unsupported mechanism");

     p = get_entry_hmac(
	 kp_obj->kp_obj, 
	 NILP(password_field) ? NULL : SDATA(password_field),
	 XINT(XCDR(mechanism)),
	 SDATA(data), SBYTES(data),
	 &allocated, xmalloc);

     obj = (allocated > 0)
	 ? make_unibyte_string(p, allocated)
	 : Qnil;
     xfree(p);
     return obj;
}

void
syms_of_keepass ()
{
    struct gcpro gcpro1, gcpro2;

#define STR_(s) #s
#define STR(s) STR_(s)
#define DEFSYM_LISP(y, s) do {	\
	y = intern(STR(s));	\
	staticpro(&y);		\
    } while(0)

    DEFSYM_LISP(Qkeepass_group, keepass-group);
    DEFSYM_LISP(Qkeepass_entry, keepass-entry);

    defsubr(&Skeepass_open);
    defsubr(&Skeepass_group_parent);
    defsubr(&Skeepass_group_uuid);
    defsubr(&Skeepass_group_name);
    defsubr(&Skeepass_group_fullpath);
    defsubr(&Skeepass_group_entry);

    defsubr(&Skeepass_entry_parent);
    defsubr(&Skeepass_entry_uuid);
    defsubr(&Skeepass_entry_field);

    defsubr(&Skeepass_entry_hmac);

    Vuuid_regex = build_string(
	"^[[:xdigit:]]\\{32\\}$"
	"\\|"	
	"^[[:xdigit:]]\\{8\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{12\\}$"
	"\\|"	
	"^{[[:xdigit:]]\\{8\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{12\\}}$"
	"\\|"	
	"^([[:xdigit:]]\\{8\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{4\\}"
	"-[[:xdigit:]]\\{12\\})$"
	"\\|"	
	"^{[[:blank:]]*0x[[:xdigit:]]\\{8\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{4\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{4\\}[[:blank:]]*,"
	"[[:blank:]]*{"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*,"
	"[[:blank:]]*0x[[:xdigit:]]\\{2\\}[[:blank:]]*}[[:blank:]]*}$"
	);
    staticpro(&Vuuid_regex);
    Vpipe = build_string("|");
    staticpro(&Vpipe);
    Vre_head = build_string("^(?:");
    staticpro(&Vre_head);
    Vre_tail = build_string(")$");
    staticpro(&Vre_tail);

    Vdefault_visible_fields = Qnil;
    staticpro(&Vdefault_visible_fields);
    {
	Lisp_Object n = Qnil;
	static const char *names[] = {
	    "Title", "UserName", "URL", "Notes",
	};
	int i;
	GCPRO1(n);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
	    n = build_string(names[i]);
	    Vdefault_visible_fields =  Fcons(n, Vdefault_visible_fields);
	}
	UNGCPRO;
    }
    Vsupported_mech_alist = Qnil;
    staticpro(&Vsupported_mech_alist);
    {
	Lisp_Object n = Qnil;
#define MECHDEF(n) {STR(n), n}
	static const struct {
	    char *name;
	    int val;
	} mechs[] = {
	    MECHDEF(md5),
	    MECHDEF(ripemd160),
	    MECHDEF(sha1),
	    MECHDEF(sha256),
	    MECHDEF(sha384),
	    MECHDEF(sha512),
	};

	int i;
	GCPRO1(n);
	for (i = 0; i < sizeof(mechs) / sizeof(mechs[0]); i++) {
	    n = intern(mechs[i].name);
	    n = Fcons(n, make_number(mechs[i].val));
	    Vsupported_mech_alist = Fcons(n, Vsupported_mech_alist);
	}
	UNGCPRO;
    }
}

static void * initialize_keepass (void *reserved)
{
    syms_of_keepass();
    CoInitialize(NULL);
    return (void *)(EMACS_INT)1;
}

static void finalize_keepass (void *data)
{
    CoUninitialize();
}

DEFINE_DLLMAIN(initialize_keepass, finalize_keepass)

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

#include "stdafx.h"
#include "keepass.h"
#include <process.h>
#using <KeePass.exe>

static inline std::string tostdstring(System::String^ s)
{
    System::IntPtr mptr = 
	System::Runtime::InteropServices
	::Marshal::StringToHGlobalAnsi(s);
    std::string str = static_cast<const char*>(mptr.ToPointer());
    System::Runtime::InteropServices::Marshal::FreeHGlobal(mptr);
    return str;
}

static inline array<System::Byte>^ tobytearray(const char *s)
{
    System::IntPtr ptr((void *)s);
    int len = strlen(s);
    array<System::Byte>^ bytes = gcnew array<System::Byte>(len);
    System::Runtime::InteropServices::Marshal::Copy(ptr, bytes, 0, len);
    return bytes;
}

template<typename T>
static inline void *tovoidptr(T p)
{
    return (p == nullptr)
	? NULL
	: static_cast<void *>(
	    System::Runtime::InteropServices::GCHandle::ToIntPtr(
		System::Runtime::InteropServices::GCHandle::Alloc(p)));
}

template<typename T> 
static inline T fromvoidptr(void *p)
{
    return
	safe_cast<T>(
	    System::Runtime::InteropServices::GCHandle::FromIntPtr(
		System::IntPtr(p)).Target);
}

static char *tocstr(std::string &s, void *(*allocator)(size_t))
{
    size_t l = s.length();
    char *ret = static_cast<char *>(allocator(l + 1));
    memcpy(ret, s.c_str(), l);
    ret[l] = 0;
    return ret;
}

#define asString(s) msclr::interop::marshal_as<System::String^>(s)
DLLEXPORT
void *open_database(const char *name, const char *passwd, 
		    const char *keyfile, int useraccount,
		    char **error)
{
    if (name == NULL) {
	*error = "Invalid filename";
	return NULL;
    }
    if (!System::IO::File::Exists(asString(name))) {
	*error = "file not found.";
	return NULL;
    }
    KeePassLib::Keys::CompositeKey^ key = nullptr;

    if (passwd != NULL || keyfile != NULL || useraccount != 0) {
	key = gcnew KeePassLib::Keys::CompositeKey;

	if (passwd != NULL && passwd[0])
	  key->AddUserKey
	      (gcnew KeePassLib::Keys::KcpPassword(tobytearray(passwd)));
	if (keyfile != NULL && keyfile[0])
	  key->AddUserKey
	      (gcnew KeePassLib::Keys::KcpKeyFile(asString(keyfile)));
	if (useraccount)
	  key->AddUserKey
	      (gcnew KeePassLib::Keys::KcpUserAccount());
    }
    KeePassLib::PwDatabase db;

    try {
	db.Open(KeePassLib::Serialization::
		IOConnectionInfo::FromPath(asString(name)),
		key, nullptr);
    } catch (System::IO::FileNotFoundException^ e) {
	*error = "file not found";
	return NULL;
    } catch (KeePassLib::Keys::InvalidCompositeKeyException^ e) {
	*error = "authetication failed.";
	return NULL;
    } catch (System::Exception^ e) {
	__declspec( thread ) static char buf[1024];
	System::IntPtr mptr = 
	    System::Runtime::InteropServices
	    ::Marshal::StringToHGlobalAnsi(e->ToString());
	strcpy_s(buf, sizeof(buf), 
		 static_cast<const char*>(mptr.ToPointer()));
	System::Runtime::InteropServices::Marshal::FreeHGlobal(mptr);
	*error = buf;
	return NULL;
    }
    
    return tovoidptr(db.RootGroup);
}

ref class OdKpfResult {
private:
    KeePassLib::Keys::CompositeKey^ key;
    bool help;
    bool ex;

public:
    OdKpfResult () : 
	key(nullptr), 
	help(false), 
	ex(false) { }
    property KeePassLib::Keys::CompositeKey^ Key {
	KeePassLib::Keys::CompositeKey^ get() {
	    return key;
	}
	void set(KeePassLib::Keys::CompositeKey^ val) {
	    key = val;
	}
    }
    property bool ShowHelpAfterClose {
	bool get() {
	    return help;
	}
	void set(bool val) {
	    help = val;
	}
    }
    property bool HasClosedWithExit {
	bool get() {
	    return ex;
	}
	void set(bool val) {
	    ex = val;
	}
    }
};

struct dlg_param {
    enum {
	original_mode = 
	DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
	DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | 
	DESKTOP_WRITEOBJECTS |DESKTOP_ENUMERATE | 
	DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK |
	DESKTOP_JOURNALRECORD,
	
	secure_mode = 
	DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
	DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | 
	DESKTOP_WRITEOBJECTS ,
    };

    // input
    HDESK desktop;
    void *ioc;

    // output
    void *Key;
    System::Windows::Forms::DialogResult result;
    bool ShowHelpAfterClose;
    bool HasClosedWithExit;
};

extern "C" static unsigned int __stdcall  SecureDialogThread(void *vparam)
{
    dlg_param *param = (dlg_param *)vparam;

    KeePassLib::Serialization::IOConnectionInfo^ ioc
	= fromvoidptr<KeePassLib::Serialization::IOConnectionInfo^>(param->ioc);

    param->Key = NULL;
    param->result = System::Windows::Forms::DialogResult::Abort;

    if (!SetThreadDesktop(param->desktop)) 
      return 0;

    System::Windows::Forms::Application::DoEvents();
    Sleep(5);
    System::Windows::Forms::Application::DoEvents();

    if (GetThreadDesktop(GetCurrentThreadId()) != param->desktop)
      return 0;
    
    /* prevent cftmon.exe */
    ImmDisableIME(0);

    System::Windows::Forms::Application::DoEvents();
    Sleep(5);
    System::Windows::Forms::Application::DoEvents();
    
    if (!SwitchDesktop(param->desktop))
      return 0;
    
    KeePass::Forms::KeyPromptForm^ kpf = 
	gcnew KeePass::Forms::KeyPromptForm();

    kpf->InitEx(ioc, false, false);
    kpf->SecureDesktopMode = true;
    param->result = kpf->ShowDialog();
    param->Key = tovoidptr(kpf->CompositeKey);
    KeePass::UI::UIUtil::DestroyForm(kpf);
    return 0;
}

DLLEXPORT
void *open_database_dlg(const char *name, int b_protected, char **error)
{
    if (name == NULL) {
	*error = "Invalid filename";
	return NULL;
    }
    if (!System::IO::File::Exists(asString(name))) {
	*error = "file not found.";
	return NULL;
    }

    KeePassLib::Serialization::IOConnectionInfo^ ioc;

    try {
	ioc =
	    KeePassLib::Serialization::IOConnectionInfo::FromPath(
		asString(name));
    } catch (System::IO::FileNotFoundException^ e) {
	*error = "file not found";
	return NULL;
    }

    for(int iTry = 0; iTry < 3; ++iTry)  {
	System::Windows::Forms::DialogResult dr;
	OdKpfResult^ kpfResult = gcnew OdKpfResult();

	if(b_protected
	   &&  KeePass::Util::WinUtil::IsAtLeastWindows2000
	   && !KeePassLib::Native::NativeLib::IsUnix()){

	    HDESK hNewDesk = NULL, hOldDesk = NULL;
	    
	    KeePass::Util::ClipboardEventChainBlocker^ ccb
		= gcnew KeePass::Util::ClipboardEventChainBlocker();

	    enum protected_desktop_error { gerror0, gerror1, gerror2, gerror3, gerror4, };
	    try {
		if ((hOldDesk = GetThreadDesktop(GetCurrentThreadId())) == NULL)
		  throw gerror0;

		dlg_param param;

		param.desktop
		    = hNewDesk
		    = CreateDesktop(
			tostdstring(gcnew System::String( /* random name */
					"D" + System::Guid::NewGuid().ToString("D")))
			.c_str(),
			NULL, NULL, 0, dlg_param::secure_mode, NULL);
		param.ioc = tovoidptr(ioc);

		if (param.desktop == NULL)
		  throw gerror1;
		
		unsigned int tid;
		uintptr_t th = _beginthreadex(
		    0, 0, SecureDialogThread,
		    static_cast<void *>(&param), CREATE_SUSPENDED, &tid);

		if (th == -1L)
		  throw gerror1;
		
		ResumeThread((HANDLE)th);
		WaitForSingleObject((HANDLE)th, INFINITE);
		CloseHandle((HANDLE)th);
		
		SwitchDesktop(hOldDesk);
		CloseDesktop(hNewDesk);

		if (param.result == System::Windows::Forms::DialogResult::OK)
		  kpfResult->Key = fromvoidptr<KeePassLib::Keys::CompositeKey^>(param.Key);
		else
		  kpfResult->Key = nullptr;

		dr = param.result;
	    } catch (protected_desktop_error e) { /* secure mode is not available */
		char buf[1024];
		FormatMessage(
		    FORMAT_MESSAGE_FROM_SYSTEM,
		    GetModuleHandle(NULL),	/* ignore, if FROM_SYSTEM */
		    GetLastError(), LANG_USER_DEFAULT,
		    buf + 1, sizeof(buf) -1,
		    NULL );
		buf[0] = '0' + e;
		MessageBox(NULL, buf, "Secure Desktop is not available", MB_OK);
		b_protected = false;
		iTry--;
		continue;
	    } catch (System::Exception^ e) {
		__declspec( thread ) static char buf[1024];
		System::IntPtr mptr = 
		    System::Runtime::InteropServices
		    ::Marshal::StringToHGlobalAnsi(e->ToString());
		strcpy_s(buf, sizeof(buf), 
			 static_cast<const char*>(mptr.ToPointer()));
		System::Runtime::InteropServices::Marshal::FreeHGlobal(mptr);
		*error = buf;
		return NULL;
	    } __finally {
		ccb->Release();
	    }
	} else { // Show dialog on normal desktop
	    KeePass::Forms::KeyPromptForm^ kpf = 
		gcnew KeePass::Forms::KeyPromptForm();
	    kpf->InitEx(ioc, false, false);

	    kpf->SecureDesktopMode = false;
	    dr = kpf->ShowDialog();
	    kpfResult->Key = kpf->CompositeKey;
	    
	}
	if(dr == System::Windows::Forms::DialogResult::Cancel)
	  break;
	
	KeePassLib::PwDatabase db;
	try {
	    db.Open(ioc, kpfResult->Key, nullptr);
	} catch (KeePassLib::Keys::InvalidCompositeKeyException^ e) {
	    continue;
	} catch (System::Exception^ e) {
	    __declspec( thread ) static char buf[1024];
	    System::IntPtr mptr = 
		System::Runtime::InteropServices
		::Marshal::StringToHGlobalAnsi(e->ToString());
	    strcpy_s(buf, sizeof(buf), 
		     static_cast<const char*>(mptr.ToPointer()));
	    System::Runtime::InteropServices::Marshal::FreeHGlobal(mptr);
	    *error = buf;
	    return NULL;
	}
	return tovoidptr(db.RootGroup);
    }
    /* cancel or retry count */
    *error = NULL;
    return NULL;
}

DLLEXPORT
void free_group(void *p)
{
    System::Runtime::InteropServices::GCHandle
	::FromIntPtr(System::IntPtr(p)).Free();
}

DLLEXPORT
void *get_group_parent(void *group)
{
    return 
	tovoidptr(fromvoidptr<KeePassLib::PwGroup^>(group)->ParentGroup);
}

template<typename T>
static inline char *get_uuid(void *entry, void *(*allocator)(size_t))
{
    enum {bufsz = sizeof("{00000000-0000-0000-0000-000000000000}")};
    char *p = (char *)allocator(bufsz);
    array<System::Byte>^ b = 
	T(fromvoidptr<T>(entry))->Uuid->UuidBytes;
    sprintf_s(p, bufsz,
	      "{%02x%02x%02x%02x"
	      "-%02x%02x"
	      "-%02x%02x"
	      "-%02x%02x"
	      "-%02x%02x%02x%02x%02x%02x}",
	      b[0], b[1], b[2], b[3],
	      b[4], b[5], b[6], b[7],
	      b[8], b[9], b[10], b[11],
	      b[12], b[13], b[14], b[15]);
    return p;
}

DLLEXPORT
char *get_group_uuid(void *group, void *(*allocator)(size_t))
{
    return get_uuid<KeePassLib::PwGroup^>(group, allocator);
}

DLLEXPORT
char *get_group_name(void *group, void *(*allocator)(size_t))
{
    return tocstr(
	tostdstring(fromvoidptr<KeePassLib::PwGroup^>(group)->Name),
	allocator);
}

DLLEXPORT
char *get_group_fullpath(void *group, const char *sep,
			 void *(*allocator)(size_t))
{
    return tocstr(
	tostdstring(fromvoidptr<KeePassLib::PwGroup^>
		 (group)->GetFullPath(asString(sep), true)),
	allocator);
}

static KeePassLib::PwUuid^ strtouuid(const char *uuid_str)
{
    try {
	array<System::Byte>^ guid = 
	    System::Guid(asString(uuid_str)).ToByteArray();
	unsigned char u[16];

	for (int i = 0; i < sizeof(u); i++)
	  u[i] = guid[i], 0;

	*(uint32_t*)u = htonl(*(uint32_t*)u);
	*(uint16_t*)(u + sizeof(uint32_t)) =
	    htons(*(uint16_t*)(u + sizeof(uint32_t)));
	*(uint16_t*)(u + sizeof(uint32_t) + sizeof(uint16_t)) =
	    htons(*(uint16_t*)(u + sizeof(uint32_t) + sizeof(uint16_t)));

	array<System::Byte>^ arr = {
	      u[0], u[1], u[2], u[3],
	      u[4], u[5], u[6], u[7],
	      u[8], u[9], u[10], u[11],
	      u[12], u[13], u[14], u[15],
	};
	return gcnew KeePassLib::PwUuid(arr);
    } catch (System::Exception^ e) {
	KeePassLib::PwUuid^ ret =
	    gcnew KeePassLib::PwUuid(false);
	return ret;
    }
}

DLLEXPORT
void *find_group_entry_by_uuid(void *group, const char *uuid_str)
{
    return tovoidptr(
	fromvoidptr<KeePassLib::PwGroup^>(group)->FindEntry(
	    strtouuid(uuid_str), true));
}

DLLEXPORT
void *find_group_child(void *group, const char *n)
{

    KeePassLib::PwGroup^ g =
	fromvoidptr<KeePassLib::PwGroup^>(group);
    System::String^ name = asString(n);

    System::Collections::Generic::IEnumerator<KeePassLib::PwGroup^>^ it
	= g->Groups->GetEnumerator();

    while(it->MoveNext()) {
	if (name->Equals(it->Current->Name, 
			 System::StringComparison::CurrentCultureIgnoreCase))
	  return tovoidptr(it->Current);
    }
    return NULL;
}

DLLEXPORT
void *find_group_entry(void *group, const char **attrs)
{
    System::Collections::Generic::IEnumerator<KeePassLib::PwEntry^>^ it
	= fromvoidptr<KeePassLib::PwGroup^>(group)->Entries->GetEnumerator();

    while(it->MoveNext()) {
	int i;
	for (i = 0; attrs[i]; i += 2) {
	    KeePassLib::Security::ProtectedString^ s =
		it->Current->Strings->Get(asString(attrs[i]));
	    if (s == nullptr)
	      goto NEXT_E;

	    pin_ptr<System::Byte> p = &s->ReadUtf8()[0];
	    if (stricmp((char *)p, attrs[i + 1]) != 0)
	      goto NEXT_E;
	}
	return tovoidptr(it->Current);
    NEXT_E:;
    }
    return NULL;
}

DLLEXPORT
void free_entry(void *p)
{
    System::Runtime::InteropServices::GCHandle
	::FromIntPtr(System::IntPtr(p)).Free();
}

DLLEXPORT
void *get_entry_parent(void *entry)
{
    return 
	tovoidptr(fromvoidptr<KeePassLib::PwEntry^>(entry)->ParentGroup);
}

DLLEXPORT
char *get_entry_uuid(void *entry, void *(*allocator)(size_t))
{
    return get_uuid<KeePassLib::PwEntry^>(entry, allocator);
}


template <bool v>
static array<System::Byte>^ 
filel_value(KeePassLib::PwEntry^ entry, System::String^ name)
{
    KeePassLib::Security::ProtectedString^ s
	= entry->Strings->Get(name);

    if (s == nullptr)
      return nullptr;
    return s->ReadUtf8();
}

template <>
static array<System::Byte>^
filel_value<true>(KeePassLib::PwEntry^ entry, System::String^ name)
{
    KeePassLib::Security::ProtectedBinary^ b
	= entry->Binaries->Get(name);
    if (b == nullptr)
      return nullptr;
    return b->ReadData();
}

DLLEXPORT char *get_entry_field(void *entry, const char *name,
				const char *vis_fields_re,
				int binaryp,
				size_t *allocated,
				void *(*allocator)(size_t))
{
    if (entry == NULL)
      return NULL;
    if (name == NULL)
      name = "Password";

    KeePassLib::PwEntry^ e = fromvoidptr<KeePassLib::PwEntry^>(entry);
    System::Text::RegularExpressions::Regex^ re =
	gcnew System::Text::RegularExpressions::Regex(
	    asString(vis_fields_re), 
	    System::Text::RegularExpressions::RegexOptions::IgnoreCase);
    
    if (!re->Match(asString(name))->Success)
      return NULL;

    array<System::Byte>^ v = binaryp
	? filel_value<true>(fromvoidptr<KeePassLib::PwEntry^>(entry), asString(name))
	: filel_value<false>(fromvoidptr<KeePassLib::PwEntry^>(entry), asString(name));
    
    *allocated = v->Length;
    char *ret = static_cast<char *>(allocator(*allocated));
    {
	pin_ptr<unsigned char> p = &v[0];
	memcpy(ret, p, *allocated);
    }
    return ret;
}

DLLEXPORT char *get_entry_hmac(void *entry, const char *field,
			       enum hmac_mech mech,
			       const unsigned char *data, size_t leng,
			       size_t *allocated,
			       void *(*allocator)(size_t))
{
    if (field == NULL)
      field = "Password";

    if (entry == NULL || field == NULL || data == NULL)
      return NULL;

    array<System::Byte>^ bdata = gcnew array<System::Byte>(leng);
    {
	pin_ptr<unsigned char> p = &bdata[0];
	memcpy(p, data, leng);
    }
    
    KeePassLib::Security::ProtectedString^ p
	= fromvoidptr<KeePassLib::PwEntry^>(entry)
	->Strings->Get(asString(field));
    if (p == nullptr)
      return NULL;

    array<System::Byte>^ key = p->ReadUtf8();

    System::Security::Cryptography::HMAC^ hmac;
    if (mech == md5)
      hmac = gcnew System::Security::Cryptography::HMACMD5(key);
    else if (mech == ripemd160)
      hmac = gcnew System::Security::Cryptography::HMACRIPEMD160(key);
    else if (mech == sha1)
      hmac =gcnew System::Security::Cryptography::HMACSHA1(key);
    else if (mech == sha256)
      hmac = gcnew System::Security::Cryptography::HMACSHA256(key);
    else if (mech == sha384)
      hmac = gcnew System::Security::Cryptography::HMACSHA384(key);
    else if (mech == sha512)
      hmac = gcnew System::Security::Cryptography::HMACSHA512(key);
    else
      return NULL;
    
    array<System::Byte>^ h = hmac->ComputeHash(bdata);
    char *ret = (char *)allocator(h->Length);
    *allocated = h->Length;
    {
	pin_ptr<unsigned char> p = &h[0];
	memcpy(ret, p, *allocated);
    }
    return ret;
}

/*
 *
 * keepass:///filename[/Group[/Group ...]]?Entry
 * Group := UUID | Name
 * 
 */

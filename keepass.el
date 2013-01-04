;; emacs-Keepass: Copyright (c) 2012 HIROSHI OOTA.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License version 2.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
;; or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
;; for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.


;; Setting:
;; (add-to-list 'after-load-alist
;; 	     '(rfc2104
;; 	       (require 'keepass)))
;;
;; requires: srfi-2.el
;; https://github.com/langmartin/site-lisp/blob/master/srfi-2.el
;;



(defvar keepass-dll)
(setq keepass-dll (load-dynamic-library "keepassdll.dll"))

(require 'url-util)
(require 'srfi-2)
(require 'rfc2104)
(require 'imap)

(defun keepass-parse-entry-spec (str)
"parse STR into entry-spec.
STR should be following form:
group-0/group-1/group-2/field1=value1&field2=value2
entry-spec is a cons entry-attrs-alist and list of group name.

example
Database/General/title=Sample1
-> (((\"title\" . \"sample1\")) \"Database\" \"General\")
"
  (let* ((tmp (reverse (split-string str "/")))
	 (entry-attrs
	  (split-string (car tmp) "&"))
	 (group (reverse (cdr tmp))))
    (cons 
     (let (alist)
	 (dolist (e entry-attrs alist)
	   (let* ((tmp (split-string e "="))
		  (key (url-unhex-string (car tmp)))
		  (value (url-unhex-string (cadr tmp))))
	     (setq alist
		   (cons (cons key value) alist)))))
     group)))

(defvar keepass-db-cache nil)

(defun keepass-subsetp (list1 list2)
  (not 
   (member nil
	   (mapcar (lambda (x)
		     (member x list2))
		   list1))))

(defun keepass-assoc-visible (vis list1)
  (let ((list1 list1)
	v)
    (while list1
      (if (keepass-subsetp vis (caar list1))
	  (setq
	   v (car list1)
	   list1 nil)
	(setq list1 (cdr list1))))
    v))

(defun keepass-get-root (file auth &optional vis)
  (or 
   (and-let* 
       ((vis (or vis '("Title" "UserName" "URL" "Notes")))
	(l (keepass-assoc-visible
	    vis keepass-db-cache))
	(r (assoc-string file (cdr l) t)))
     (cdr r))
   (and-let*
       ((root (keepass-open file auth vis))
	(vis (or vis '("Title" "UserName" "URL" "Notes")))
	(l (or (keepass-assoc-visible
		vis keepass-db-cache)
	       (let ((nl (list vis)))
		 (add-to-list 'keepass-db-cache nl)
		 nl))))
     (setcdr l (cons (cons file root) 
		     (cdr l)))
     root)))
(defconst keepass-password-regex
  "^keepass:\\(.*\\.kdbx?\\)\\?\\(.*/[^#]+\\)\\(#[^#]+\\)?")

(defun keepass-hmac-urn (password mech data)
  (if (string-match keepass-password-regex password)
      (and-let*
	  ((file (match-string 1 password))
	   (attrs (match-string 2 password))
	   (pwd-fld (list
		     (and (match-string 3 password)
			  (substring 
			   (match-string 3 password) 1))))
	   (root (keepass-get-root 
		  file t 
		  (and (car pwd-fld)
		       (cons (car pwd-fld)
			     '("Title" "UserName" "URL" "Notes")))))
	   (ent (keepass-group-entry
		 root
		 (keepass-parse-entry-spec
		  attrs)))
	   (dgst
	    (keepass-entry-hmac 
	     ent (car pwd-fld) mech data)))
	(apply 'concat
	       (mapcar '(lambda (x) (format "%02x" x))
		       (string-to-vector dgst))))))

(defun keepass-login-auth (user password func)
  (and 
   (string-match keepass-password-regex password)
   (and-let*
       ((file (match-string 1 password))
	(attrs (match-string 2 password))
	(pwd-fld (list
		  (and (match-string 3 password)
		       (substring 
			(match-string 3 password) 1))))
	(root (keepass-get-root 
	       file t 
	       (and (car pwd-fld)
		    (cons (car pwd-fld)
			  '("Title" "UserName" "URL" "Notes")))))
	(ent (keepass-group-entry
	      root
	      (keepass-parse-entry-spec
	       attrs)))
	(password 
	 (keepass-entry-field
	  ent 
	  (car pwd-fld))))
     (funcall func user password))))


(defadvice imap-login-auth
  (around keepass-imap-login-auth activate)
  "adviced by keepass."
  (let ((ok (keepass-login-auth
	     imap-username imap-password
	     (lambda (user password)
	       (imap-ok-p
		(imap-send-command-wait
		 (concat "LOGIN \""
			 (imap-quote-specials user)
			 "\" \""
			 (imap-quote-specials password)
			 "\"")))))))
    (if ok
      (setq ad-return-value ok)	
    ad-do-it)))

(defadvice rfc2104-hash
  (around keepass-rfc2104-hash-advice activate)
  "adviced by keepass."
  (let ((kp
	 (keepass-hmac-urn 
	  (ad-get-arg 3) ; key
	  (ad-get-arg 0) ; hash
	  (ad-get-arg 4)))) ; data
    (if kp
	(setq ad-return-value kp)
      ad-do-it)))

;;after-load-functions

;; 

(provide 'keepass)

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

(defun keepass-hmac-urn (str mech data)
  (if (string-match "^keepass:\\(.*\\.kdbx?\\)\\?\\(.+\\)" str)
      (and-let*
	  ((file (match-string 1 str))
	   (attrs (match-string 2 str))
	   (root (if (assoc file keepass-db-cache)
		     (cdr (assoc file keepass-db-cache))
		   (keepass-open file t)))
	   (ent (keepass-group-entry
		 root
		 (keepass-parse-entry-spec
		  attrs)))
	   (digest
	    (keepass-entry-hmac ent mech data)))
	;; cache 
	(unless (assoc file keepass-db-cache)
	  (add-to-list 'keepass-db-cache
		       (cons file root)))
	(apply 'concat
	       (mapcar '(lambda (x) (format "%02x" x))
		       (string-to-vector digest))))))

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

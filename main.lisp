(defpackage oauth2-client
  (:nicknames #:oauth2-client/main)
  (:use #:cl
        #:alexandria
        #:quri
        #:split-sequence)
  (:import-from #:uiop
                #:strcat)
  (:import-from #:dexador)
  (:import-from #:jonathan)
  (:export #:provider
           #:provider-client-id
           #:provider-client-secret
           #:provider-redirect-uri
           #:provider-authorize-url
           #:provider-access-token-url
           #:provider-resource-owner-url
           #:provider-scope-separator
           #:token
           #:token-access-token
           #:token-refresn-token
           #:token-type
           #:token-expires-in
           #:token-scope
           #:token-obtained-at
           #:token-data
           #:oauth2-error
           #:oauth2-error-type
           #:oauth2-error-description
           #:oauth2-error-uri
           #:authorization-url
           #:fetch-access-token-by-auth-code
           #:fetch-resource
           #:fetch-resource-owner-details
           #:extract-url-authorization-code))
(in-package :oauth2-client)

(defclass provider ()
  ((client-id :initarg :client-id
              :accessor provider-client-id
              :initform (error "CLIENT-ID required.")
              :type string)
   (client-secret :initarg :client-secret
                  :accessor provider-client-secret
                  :initform (error "CLIENT-SECRET required.")
                  :type string)
   (redirect-uri :initarg :redirect-uri
                 :accessor provider-redirect-uri
                 :initform (error "REDIRECT-URI required.")
                 :type string)
   (authorize-url :initarg :authorize-url
                  :accessor provider-authorize-url
                  :initform (error "AUTHORIZE-URL required.")
                  :type string)
   (access-token-url :initarg :access-token-url
                     :accessor provider-access-token-url
                     :type string)
   (resource-owner-url :initarg :resource-owner-url
                       :accessor provider-resource-owner-url
                       :type string)
   (default-scope :initarg :default-scope
                  :accessor provider-default-scope
                  :initform nil
                  :type list)
   (scope-separator :initarg :scope-separator
                    :accessor provider-scope-separator
                    :initform ","
                    :type string)))

(defstruct token
  (access-token nil :type string :read-only t)
  (refresh-token nil :type (or null string))
  (type nil :type string :read-only t)
  (expires-in nil :type (or null integer) :read-only t)
  (scope nil :type (or null string))
  (obtained-at nil :type fixnum)
  (data nil :type list))


(define-condition oauth2-error (error)
  ((type :reader oauth2-error-type :initarg :type :type string)
   (description :reader oauth2-error-description :initarg :description :type string)
   (uri :reader oauth2-error-uri :initarg :uri :type string)
   (data :reader oauth2-error-data :initarg :data :type list))
  (:report (lambda (err stream)
             (format stream
                     "~A: ~A.~@[(~A)~]"
                     (oauth2-error-type err)
                     (oauth2-error-description err)
                     (oauth2-error-uri err)))))


(defun add-query-params (url params)
  (let ((uri (uri url)))
    (render-uri (make-uri :scheme (uri-scheme uri)
                          :host (uri-host uri)
                          :port (uri-port uri)
                          :path (uri-path uri)
                          :query (append (uri-query-params uri)
                                         params)))))

(defmethod generate-state ((provider provider))
  (format nil "~X" (+ (expt 1024 12) (random (expt 1024 12)))))

(defgeneric authorization-params (provider &rest params))

(defmethod authorization-url ((provider provider) &key state scope response-type options)
  "Builds the authorization URL"
  (with-slots (client-id authorize-url default-scope redirect-uri scope-separator) provider
    (add-query-params authorize-url
                      (append `(("client_id" . ,client-id)
                                ("response_type" . ,(or response-type "code"))
                                ("state" . ,(or state (generate-state provider)))
                                ("scope" . ,(reduce (lambda (all s)
                                                      (strcat all scope-separator s))
                                                    (or scope default-scope)))
                                ("redirect_uri" . ,redirect-uri))
                              (authorization-params provider)
                              options))))

(defmethod fetch-access-token-by-auth-code ((provider provider) code &key options)
  (with-slots (client-secret access-token-url redirect-uri scope-separator) provider
    (let* ((response (dex:post (add-query-params access-token-url
                                                 (append `(("grant_type" . "authorization_code")
                                                           ("code" . ,code)
                                                           ("client_secret" . ,client-secret)
                                                           ("redirect_uri" . ,redirect-uri))
                                                         options))))
           (data (jojo:parse response)))
      (make-token :access-token (getf data :|access_token|)
                  :type (getf data :|token_type|)
                  :refresh-token (getf data :|refresh_token|)
                  :expires-in (getf data :|expires_in|)
                  :scope (split-sequence scope-separator (or (getf data :|scope|) ""))
                  :obtained-at (get-universal-time)
                  :data data))))

(defmethod fetch-resource ((provider provider) method url token)
  (with-slots (resource-owner-url) provider
    (handler-case
        (jojo:parse (dex:request method url
                                 :headers `(("Authorization" . (format nil "~A ~A"
                                                                       (or (token-type token) "Bearer")
                                                                       (token-access-token token))))))
      (dex:http-request-bad-request (e)
        (let ((data (jojo:parse (dex:response-body e))))
          (error (make-condition 'oauth2-error
                                 :type (getf data :|error|)
                                 :description (getf data :|error_description|)
                                 :data data)))))))

(defmethod fetch-resource-owner-details ((provider provider) token)
  (fetch-resource provider (povider-resource-owner-url povider)))

(defun token-expired-p (token)
  (when (token-expires-in token)
    (> (get-universal-time)
       (+ (token-obtained-at token) (token-expires-in token)))))


(defun extract-url-authorization-code (url)
  (assoc-value (uri-query-params (uri url)) "code"
               :test #'string=))

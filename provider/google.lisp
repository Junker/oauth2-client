(defpackage oauth2-client/provider/google
  (:nicknames #:oauth2-client/google)
  (:use #:cl
        #:oauth2-client)
  (:export #:google-provider
           #:google-provider-prompt
           #:google-provider-access-type
           #:google-provider-hosted-domain))
(in-package :oauth2-client/provider/google)

(defclass google-provider (provider)
  ((prompt :initarg :prompt
           :accessor google-provider-prompt
           :initform nil
           :documentation "If set, this will be sent to google as the \"prompt\" parameter.")
   (access-type :initarg :access-type
                :accessor google-provider-access-type
                :initform nil
                :documentation "If set, this will be sent to google as the \"access_type\" parameter.")
   (hosted-domain :initarg :hosted-domain
                  :accessor google-provider-hosted-domain
                  :initform nil
                  :documentation "If set, this will be sent to google as the \"hd\" parameter."))
  (:default-initargs
   :authorize-url "https://accounts.google.com/o/oauth2/v2/auth"
   :access-token-url "https://oauth2.googleapis.com/token"
   :resource-owner-url "https://openidconnect.googleapis.com/v1/userinfo"
   :default-scope '("openid" "email" "profile")
   :scope-separator " "))


(defmethod authorization-params ((provider google-provider))
  (with-slots (hosted-domain access-type prompt) provider
    (append (and hosted-domain `(("hd" . ,hosted-domain)))
            (and prompt `(("prompt" . ,prompt)))
            (and access-type `(("access-type" . ,access-type))))))

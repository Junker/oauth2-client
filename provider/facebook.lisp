(defpackage oauth2-client/provider/facebook
  (:nicknames #:oauth2-client/facebook)
  (:use #:cl
        #:alexandria
        #:oauth2-client)
  (:import-from #:uiop
                #:strcat)
  (:export #:facebook-provider))
(in-package :oauth2-client/provider/facebook)

(define-constant +base-graph-url+ "https://graph.facebook.com/"
  :test #'equal)


(defclass facebook-provider (provider)
  ((graph-api-ver :initarg :graph-api-ver
                  :reader facebook-provider-graph-api-ver
                  :initform (error "GRAPH-API-VER required.")
                  :documentation "The Graph API version to use for requests.")
   (fields :initarg :fields
           :reader facebook-provider-fields
           :documentation "The fields to look up when requesting the resource owner"))
  (:default-initargs
   :default-scope '("public_profile" "email")
   :fields '("id" "name" "first_name" "last_name"
             "email" "hometown" "picture.type(large){url,is_silhouette}"
             "gender" "age_range")))

(defmethod initialize-instance ((provider facebook-provider) &key)
  (with-slots (authorize-url access-token-url resource-owner-url graph-api-ver) provider
    (setf authorize-url (strcat +base-graph-url+ graph-api-ver "/dialog/oauth")
          access-token-url (strcat +base-graph-url+ graph-api-ver "/oauth/access_token")
          resource-owner-url (format nil "~A/~A/me?fields=~{~A~^,~}"
                                     +base-graph-url+ graph-api-ver fields))))

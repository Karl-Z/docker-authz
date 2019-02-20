(ns authz.contenttype
    (:require [ring.util [request :as req] [response :as res]]))


(defn- content-type-request
  [request ctype]
  (if (and (not (req/content-type request))
           (req/content-length request))
    (assoc-in request [:headers "content-type"] ctype)
    request))

(defn- content-type-response
  [response ctype]
  (if (and (not (res/get-header response "content-type"))
           (res/get-header response "content-length"))
    (res/content-type response ctype)
    response))

(defn wrap-content-type
  "Middleware that adds a content-type header to the request/response if one is not
  found.  It defaults to 'application/octet-stream'.

  Accepts the following options:
  :request - add content type in the request
  :response - add content type in the response

  Example:
  (wrap-content-type handler :request \"application/json\")"
  ([handler & {req-ctype :request
               res-ctype :response
               :or {req-ctype "application/octet-stream"
                    res-ctype "application/octet-stream"}}]
   (fn
     ([request]
      (-> request
          (content-type-request req-ctype)
          (handler)
          (content-type-response res-ctype)))
     ([request response raise]
      (-> request
          (content-type-request req-ctype)
          (handler #(response (content-type-response % res-ctype)) raise))))))

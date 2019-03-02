(ns authz.wrap-contenttype
  (:require [clojure.string :as str])
  (:require [ring.util.response :as response])
  (:require [clojure.tools.logging :as log])
  (:require [ring.util [request :as req] [response :as res]]))


(defn- contenttype-request
  [request ctype]
  (if (and (not (req/content-type request))
           (req/content-length request))
    (assoc-in request [:headers "content-type"] ctype)
    request))

(defn- contenttype-response
  [response ctype]
  (if (and (not (res/get-header response "content-type"))
           (res/get-header response "content-length"))
    (res/content-type response ctype)
    response))

(defn wrap-contenttype
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
          (contenttype-request req-ctype)
          (handler)
          (contenttype-response res-ctype)))
     ([request response raise]
      (-> request
          (contenttype-request req-ctype)
          (handler #(response (contenttype-response % res-ctype)) raise))))))

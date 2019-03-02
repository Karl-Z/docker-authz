(ns authz.core)

;;; data source definitions
(defsource txtfile-api
  :type passwd
  :cache true
  :parameters {:path "resources/docker-api.db"})


(defsource txtfile-users
  :type passwd
  :parameters {:path "resources/users.db"})

(defsource txtfile-superusers
  :type passwd
  :parameters {:path "resources/users.db" :match "admin-.*"})

(defsource txtfile-usergroups
  :type group
  :parameters {:path "resources/user-groups.db"})

(defsource txtfile-supergroups
  :type group
  :parameters {:path "resources/user-groups.db" :match "admin-.*"})

(defsource txtfile-hosts
  :type passwd
  :parameters {:path "resources/hosts.db"})

(defsource txtfile-hostgroups
  :type group
  :parameters {:path "resources/host-groups.db"})

(defsource txtfile-deploymentenvironments
  :type group
  :parameters {:path "resources/deployment-environments.db"})

;;; validator definitions
;; validate one aspect of request
;; :path - input value from the path of request, same as get-in
;; :transform - a group of tuples of regexp and replacement
;; :validator - call the function with input value or transformed input value
;; :optional - ignore input and return true

(defrule valid-uri
  :path [:body "RequestUri"]
  :transform ["^/v\\d\\.\\d\\d" ""
              "/([^/?]+)[?/].*" "/$1"]
  :validator txtfile-api)

(defrule valid-user
  :path [:body "User"]
  :validator txtfile-users)

(defrule super-user
  :path [:body "User"]
  :validator txtfile-superusers)

(defrule valid-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-usergroups)

(defrule super-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-supergroups)

;; some derived arguments are stored in json's "@" key
(defrule valid-host
  :path [:body "Host"]
  :validator txtfile-hosts)

(defrule valid-hostgroup
  :path [:body "HostGroup"]
  :validator txtfile-hostgroups)

;; lookup function for user group identification
(deflookup usergroup-lookup
  :dominion [txtfile-usergroups]
  :return name->group)

;; given host name, look up host group 
(deflookup hostgroup-lookup
  :dominion [txtfile-hostgroups]
  :return name->group)

;; lookup deployment environment
(deflookup deploymentenvironment-lookup
  :dominion [txtfile-deploymentenvironments]
  :return name->group)

;; add callback function to the predefined hooks
(add-hook authz.wrap-usergroup/wrap-usergroup-hook usergroup-lookup)
(add-hook authz.wrap-hostgroup/wrap-hostgroup-hook hostgroup-lookup)
(add-hook authz.wrap-deploymentenvironment/wrap-deploymentenvironment-hook
          deploymentenvironment-lookup)

;; re-subset?: checking subset1 again subset2 which contains regexp that must
;;             match entry in subset1

;; read operation
(defrule read-method
  :path [:body "RequestMethod"]
  :validator #{"GET"})

(defrule write-method
  :path [:body "RequestMethod"]
  :validator #{"POST" "PUT"})

(defrule delete-method
  :path [:body "RequestMethod"]
  :validator #{"DELETE"})

(defrule all-method
  :path [:body "RequestMethod"]
  :validator #{"GET" "POST" "PUT" "DELETE"})

(defrule repo-tags
  :path [:body "ResponseBody" "RepoTags"]
  :validator #(re-subset? % #{"docker.io/busybox.*"}))

(defrule post-method
  :path ["RequestMethod"]
  :validator #(= % "POST"))

(defrule have-labels
  :path [:body "Labels"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))

(defrule drop-caps
  :path [:body "HostConfig" "CapDrop"]
  :validator #(subset? #{"NET_BIND_SERVICE" "SETUID" "SETGID"} %))

(defrule have-caps
  :path [:body "HostConfig" "CapAdd"]
  :type :optional
  :validator #(subset? % #{"SYS_PTRACE"}))

(defrule allowed-network
  :path ["NetworkMode"]
  :type :optional
  :validator #{"bridge" "none"})

(defrule allowed-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"dev" "qa" "prod" "uat"})

(defrule denied-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"uat"})

(defrule allowed-mounts
  :path [:body "HostConfig" "Mounts"]
  :validator #(re-subset? % #{".*=/opt" ".*=/var/log" ".*=/user/local"}))

(defrule allowed-volumes
  :path [:body "Volumes"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))

;;; Policies
;; :base        Policy applied on specific version
;; :uri         RequestUri applied
;; :condition   Method to aggrate all rules' results, possible value:
;;              :all    policy return true only if all rules return true
;;              :none   policy return true only if all rules return false
;;              :some   policy return true if some of the rules return true
;;              :one    policy return true if only one rule return true

;; default policy to apply on all requests and responses
(defpolicy default-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :control :required
  :condition :all
  :rules [valid-uri valid-user valid-host valid-hostgroup])

(defpolicy deploy-environment-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :control :required
  :rules [allowed-environments])

(defpolicy denied-deploy-environment-policy
  :base #{"/v1.26"}
  :uri "/.*"
  :control :required
  :condition :none
  :rules [denied-environments])

(defpolicy container-create
  :base #{"/v1.26"}
  :uri "/containers/create"
  :control :requsite
  :condition :some
  :rules [super-user super-usergroup])

(defpolicy build
  :base #{"/v1.26"}
  :uri "/build"
  :control :requsite
  :rules [super-user])

#_(defpolicy user1-have-hstgrp1
  :base #{"/v1.26"}
  :uri "/.*"
  :rules [#{"hostgroup1"} #{"user1"}]
)

(defproject authz "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [org.clojure/tools.logging "0.4.1"]
                 [org.clojure/data.csv "0.1.4"]
                 [org.clojure/tools.namespace "0.3.0-SNAPSHOT"]
	         [ring/ring-core "1.7.1"]
                 [ring/ring-servlet "1.7.1"]
                 [ring/ring-jetty-adapter "1.7.1"]
                 [ring/ring-mock "0.3.2"]
                 [ring/ring-json "0.5.0-beta1"]
                 [ring/ring-defaults "0.3.2"]
                 [ring/ring-codec "1.1.1"]
                 [cheshire "5.8.1"]
                 [clout "2.2.1"]
                 [compojure "1.6.1"]
                 [org.hjson/hjson "1.0.0"]
                 [net.apribase/clj-dns "0.1.0"]
                 [radicalzephyr/ring.middleware.logger "0.6.0"]
                 [log4j/log4j "1.2.17"
                  :exclusions [javax.mail/mail
                               javax.jms/jms
                               com.sun.jmdk/jmxtools
                               com.sun.jmx/jmxri]]]
  
  :repositories [["sonatype-oss-public"
                  "https://oss.sonatype.org/content/groups/public/"]]
  :plugins [[lein-ring "0.12.4"]]
  :ring {:handler authz.app/app
         :port 8080
         :async? false})

;; [com.brweber2/clj-dns "0.0.2"]

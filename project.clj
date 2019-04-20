(defproject docker-authz "0.1.0"
  :description "Docker's complete/complex authz plugin"
  :url "https://github.com/carlzhc/docker-authz"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [org.clojure/tools.logging "0.4.1"]
                 [org.clojure/data.csv "0.1.4"]
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
                 [net.apribase/clj-dns "0.1.0"]
                 [radicalzephyr/ring.middleware.logger "0.6.0"]
                 [environ "1.1.0"]
                 [log4j/log4j "1.2.17"
                  :exclusions [javax.mail/mail
                               javax.jms/jms
                               com.sun.jmdk/jmxtools
                               com.sun.jmx/jmxri]]]
  :profiles {:dev {:env {:docker-policy "resources/config/policy.clj"}}}
  :repositories [["sonatype-oss-public"
                  "https://oss.sonatype.org/content/groups/public/"]]
  :plugins [[lein-ring "0.12.5"]
            [lein-codox "0.10.6"]
            [lein-environ "1.1.0"]
            [carlzhc/lein-tar "3.3.0"]
            [lein-rpmbuild "0.1.1"]]
  :ring {:handler authz.app/app
         :port 8080
         :async? false}
  :tar {:uberjar true
        :format :tar-gz
        :jar-path "/libexec/docker-authz"}
  :war-exclusions [#"^config/"]
  :jar-exclusions [#"^config/"]
  :uberjar-exclusions [#"^config/"]
  :rpmbuild {:Release "1%{?dist}"
             :Summary "Docker authorization service"
             :Group "Application"
             :%description
             "A complete/complex Docker authorization service that runs standalone directly on a host,
or can be isolated in a container.

User’s basic authentication is provided by Docker daemon when it enables TLS verification.

"
             :%post ["/usr/bin/systemctl daemon-reload"]
             :%config ["/etc/docker/policies" "/etc/sysconfig/%name"]
             :%doc ["README.org"]})

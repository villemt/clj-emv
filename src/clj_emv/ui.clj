(ns clj-emv.ui
  "Simple text based ui"
  (:require [clj-emv.cvm :as cvm])
  (:require [clj-emv.date :as date])
  (:require [clj-emv.tags :as tags])
  (:require [clj-emv.utils :as utils])
  (:require [clj-emv.file :as file])
  (:require [clj-emv.pcsc :as pcsc])
  (:require [clojure.pprint :as pprint])
  (:require [clj-emv.restrictions :as restrictions]))

(defn print-tag[tag]
  (let [tag-number (:tag tag)
        tag-info (file/find-tag-info tag-number)]
    (println " -> Tag (hex):\t" (utils/hexify tag-number) (:name tag-info))
    (println "    Data (hex):\t" (str (utils/bytes-to-hex-string (:value tag))))))

(defn print-response[apdu]
  (let [sw1 (:sw1 apdu)
        sw2 (:sw2 apdu)
        data (:data apdu)
        desc (tags/status-bytes-to-description sw1 sw2)
        tags (tags/parse-full-tlv data)]
    (println
     "Response (hex):"
     (utils/hexify-list [sw1 sw2])
     (:status desc)
     " -> Data (hex):" (str (utils/bytes-to-hex-string (:data apdu))))
    (dorun (map print-tag tags))))

(defn get-applications[channel sfi]
  (loop [applications []
         rec 1]
    (let [response (pcsc/read-record-command channel sfi rec)
          success (:success response)]
      (if success
        (do
          (println "READ RECORD - application:")
          (print-response response)))
      (if (not success)
        applications
        (recur (conj applications (tags/response-to-application response)) (inc rec))))))

(defn println-with-stars[& args]
  (let [line (str "*** " (apply str args) " ***")
        stars (apply str (repeat (count line) "*"))]
    (println "")
    (println stars)
    (println line)
    (println stars)
    (println "")))

(defn exit-program[message]
  (println-with-stars "PROGRAM TERMINATED: " message)
  (System/exit 0))

(defn valid-index?[idx min max]
  (and (integer? idx) (>= idx min) (<= idx max)))

(defn select-terminal[terminals]
  (defn print-terminal[item]
    (let [[idx terminal] item]
      (println idx ")" (:name terminal) (if (:is-card-present terminal) "(card present)" ""))))

  (if (empty? terminals)
      (exit-program "no terminals found"))

  (println "Please select a terminal:")
  (dorun (map print-terminal (map-indexed vector terminals)))

  (let [idx (read-string (read-line))]
    (if (or (not (integer? idx)) (< idx 0) (>= idx (count terminals)))
      (exit-program "invalid index value"))
      (nth terminals idx)))

(defn select-environment[]
  (println "Please select the payment environment:")
  (println "0 ) Payment System Environment (PSE)")
  (println "1 ) Proximity Payment System Environment (PPSE)")
  (let [idx (read-string (read-line))]
    (if (valid-index? idx 0 1)
      (condp = idx
        0 tags/PSE
        1 tags/PPSE)
      (exit-program "invalid environment selection"))))

(defn print-application[app]
  (println
   (:preferred-name app)
   "\t" (:label app)
   "\tAID (hex):" (utils/bytes-to-hex-string (:aid app))))

(defn- print-application-with-index[item]
  (let [[idx app] item]
    (print idx ") ")
    (print-application app)))

(defn- select-application[applications]
  (if (empty? applications)
      (exit-program "no applications found"))

  (println "Please select an application:")
  (dorun (map print-application-with-index (map-indexed vector applications)))

  (let [idx (read-string (read-line))]
    (if (or (not (integer? idx)) (< idx 0) (>= idx (count applications)))
      (exit-program "invalid index value"))
      (nth applications idx)))

(defn select-application-in-environment[channel environment]
  (let [select-response (pcsc/select-command channel environment)]
    (println "SELECT - environment:")
    (print-response select-response)
    (if (:success select-response)
      (let [sfi (tags/tag-value-as-number (tags/get-tag select-response tags/SHORT_FILE_IDENTIFIER))
            application (if (= environment tags/PSE)
                          (select-application (get-applications channel sfi))
                          (tags/response-to-application select-response))]
        (println "Selected application:")
        (print-application application)
        application)
      (exit-program "Payment environment selection failed"))))

(defn select-single-application[channel application]
  (let [select-response (pcsc/select-command channel (:aid application))]
    (println "SELECT - AID")
    (print-response select-response)
    (tags/get-pdol select-response)))

(defn initiate-application-process[channel pdol]
  (let [response (pcsc/get-processing-options-command channel pdol)]
    (println "GET PROCESSING OPTIONS - PDOL:")
    (print-response response)
    (let [data (:data response)
          aip-tag (tags/get-tag response tags/APPLICATION_INTERCHANGE_PROFILE)
          aip (apply tags/aip-from-bytes (:value aip-tag))
          afl-tag (tags/get-tag response tags/APPLICATION_FILE_LOCATOR)
          partitions (partition 4 (:value afl-tag))
          afls (map #(apply tags/afl-from-bytes %) partitions)]
      (println "AIP:")
      (pprint/pprint aip)
      (println "AFL:")
      (pprint/pprint afls)

      [aip (:value aip-tag) afls])))


(defn get-afl-tags[channel afls]
  (defn read-afl-records[channel afl]
    (let [sfi (:sfi afl)]
      (loop [tags '()
             rec (:first-rec afl)]
        (if (> rec (:last-rec afl))
          tags
          (let [response (pcsc/read-record-command channel sfi rec)
                data (:data response)
                new-tags (concat tags (tags/parse-full-tlv data))]
            (recur new-tags (inc rec)))))))

  (flatten (map #(read-afl-records channel %) afls)))

(defn read-afl-tags[channel afls]
 (let [tags (get-afl-tags channel afls)]
    (dorun (map print-tag tags))
    tags))

(defn check-processing-restrictions[
  application-version-number
  application-usage-control
  issuer-country-code-tag
  application-effective-date
  application-expiration-date]
  (let [tvr-application-version-number (restrictions/check-application-version-number application-version-number)
        usage-control-result (restrictions/check-application-usage-control application-usage-control issuer-country-code-tag)
        tvr-application-dates (restrictions/check-application-dates application-effective-date application-expiration-date)
        issuer-country-code (utils/bytes-to-hex-string (:value issuer-country-code-tag))
        issuer-country-name (file/find-country issuer-country-code)]
    (println "Application Version Number:" application-version-number)

    (println "\nApplication Usage Control:")
    (pprint/pprint application-usage-control)

    (println "\nIssuer Country Code (hex):" issuer-country-code issuer-country-name)

    (println "\nApplication Effective Date:" (date/print-date application-effective-date))
    (println "\nApplication Expiration Date:" (date/print-date application-expiration-date))

    (println-with-stars "Processing Restrictions function completed")
    (merge tvr-application-version-number tvr-application-dates)))

(defn perform-cvm[cvm-list-tag currency-tag]
  (let [cvm (cvm/parse-cvm-list-tag cvm-list-tag currency-tag)]

    (println "Application Currency Code (hex):" (:currency-code cvm))
    (println "CVM - X: " (:x cvm))
    (println "CVM - Y: " (:y cvm))
    (dorun (map pprint/pprint (:rules cvm))))

    ; TODO: validate each rule separately

    (println-with-stars "Cardholder Verification Method (CVM) completed")

    ; Return TVR and TSI
    [{} {:cardholder-verification-was-performed true}]
  )







(ns clj-emv.ui
  "Simple text based ui"
  (:require [clj-emv.action-analysis :as action-analysis])
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


(defn print-dol-tag[dol-tag-info]
  (let [tag-number (:tag-number dol-tag-info)
        tag-name (:name (:tag-info dol-tag-info))
        object-length (:object-length dol-tag-info)]
  (println " -> Tag (hex):\t" (utils/hexify tag-number) tag-name)
  (println "    Length:\t" object-length)))

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
          (println "READ RECORD" (str "(SFI: " sfi " REC: " rec ") - application:"))
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
    (let [[pdol pdol-tags] (tags/get-pdol select-response)]

      (println "Card PDOL response tags:")
      (dorun (map print-dol-tag pdol-tags))

      (println "PDOL Sent to card: " (utils/bytes-to-hex-string pdol))

      pdol)))

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
      (println "AIP (hex):" (utils/bytes-to-hex-string (:value aip-tag)))
      (pprint/pprint aip)
      (println "AFL (hex):" (utils/bytes-to-hex-string (:value afl-tag)))
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

(defn perform-terminal-risk-management[lower-consecutive-offline-limit-tag upper-consecutive-offline-limit-tag atc last-online-atc-register]

  ; TODO: Floor Limit check

  ; TODO: Random Transaction Selection, for online processing

  ; Velocity Checking
  (println "Lower Consecutive Offline Limit:" lower-consecutive-offline-limit-tag)
  (println "Upper Consecutive Offline Limit:" upper-consecutive-offline-limit-tag)

  (println "ATC:" atc)
  (println "Last Online ATC Counter:" last-online-atc-register)

  (println-with-stars "Terminal Risk Management completed")

  ; Return TVR and TSI
  [{} {:terminal-risk-management-was-performed true}])

(defn map-filter[value predicate]
  (into {} (filter predicate value)))

(defn pprint-if-true[value]
  (pprint/pprint (map-filter value (fn [[k v]] (true? v)))))

(defn perform-terminal-action-analysis[channel tvr action-code-default-tag action-code-denial-tag action-code-online-tag cdol1-tag dynamic-number-response data-authentication-code]
  (let [iac-default-str (tags/tag-value-as-hex-string action-code-default-tag)
        iac-denial-str (tags/tag-value-as-hex-string action-code-denial-tag)
        iac-online-str (tags/tag-value-as-hex-string action-code-online-tag)

        ;TODO: Add TAC support

        iac-default (apply tags/tvr-from-bytes (:value action-code-default-tag))
        iac-denial (apply tags/tvr-from-bytes (:value action-code-denial-tag))
        iac-online (apply tags/tvr-from-bytes (:value action-code-online-tag))]

  (println "Terminal has no online ability. The issuers's conditions to reject the transaction:")
  (println "Issuer Action Code - Default (hex):" iac-default-str)
  (pprint-if-true iac-default)

  (println "\nThe issuer's conditions to reject the transaction:")
  (println "Issuer Action Code - Denial (hex):" iac-denial-str)
  (pprint-if-true iac-denial)

  (println "\nThe issuer's conditions to approve the transaction online:")
  (println "Issuer Action Code - Online (hex):" iac-online-str)
  (pprint-if-true iac-online)

  ; TODO: compare IACs + TAC with the TVR. Currently, only offline transactions are supported.

  ; TODO: Ask the amount from the user and generate dynamic values
  (def transaction-details
    {0x9F02 [0 0 0 0 0 1]   ;Amount, Authorised
     0x9F03 [0 0 0 0 0 0]   ;Amount, Other
     0x95   [0 0 0 0 0]     ;TVR
     0x9A   [0x16 0x01 0x19];Transaction Date
     0x9F21 [0 0 0]         ;Transaction time
     0x9F34 [0 0 0]         ;Cardholder Verification
     0x9F45 data-authentication-code
     0x9F4C (:data dynamic-number-response)})

  ; Perform Application Cryptogram generation
  ; TODO: Implement the full AC generation logic. Currently hard-coded to request ARQC from the card without CDA.
  (let [ac-p1 (action-analysis/generate-ac-p1 :arqc false)
        ac-data (action-analysis/generate-ac-data cdol1-tag dynamic-number-response transaction-details)]

    (println "\nCard Risk Management Data Object List 1 (CDOL1) (hex):" (tags/tag-value-as-hex-string cdol1-tag) "\n")
    (dorun (map print-dol-tag (tags/get-dol-tags (:value cdol1-tag))))

    (println "\nGenerate AC Data (hex):" (utils/bytes-to-hex-string ac-data) "\n")

    (let [ac-response (pcsc/generate-ac-command channel ac-p1 ac-data)]
      (print-response ac-response))

    (println-with-stars "Terminal Action Analysis completed"))))

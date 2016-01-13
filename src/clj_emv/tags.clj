(ns clj-emv.tags
  "Methods for parsing EMV tags"
  (:use clj-emv.bit-ops)
  (:use clj-emv.utils))

(def PSE (vec (string-to-bytes "315041592E5359532E4444463031")))

(def PPSE (vec (string-to-bytes "325041592E5359532E4444463031")))

(def COMMAND_TEMPLATE 0x83)

(def SHORT_FILE_IDENTIFIER 0x88)

(def APPLICATION_INTERCHANGE_PROFILE 0X82)
(def APPLICATION_FILE_LOCATOR 0x94)

(def CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX 0x8F)

(def PROCESSING_OPTIONS_DATA_OBJECT_LIST 0x9F38)

(def ISSUER_PUBLIC_KEY_CERTIFICATE 0x90)
(def ISSUER_PUBLIC_KEY_EXPONENT 0x9F32)
(def ISSUER_PUBLIC_KEY_REMAINDER 0x92)

(def SIGNED_APPLICATION_DATA 0x93)

(def ICC_PUBLIC_KEY_CERTIFICATE 0x9F46)
(def ICC_PUBLIC_KEY_EXPONENT 0x9F47)
(def ICC_PUBLIC_KEY_REMAINDER 0x9F48)

(def SIGNED_DYNAMIC_APPLICATION_DATA 0x9F4B)

(def APPLICATION_PRIMARY_ACCOUNT_NUMBER 0x5A)

(def APPLICATION_IDENTIFIER 0X4F)
(def APPLICATION_LABEL 0x50)
(def APPLICATION_PRIORITY_INDICATOR 0x87)
(def APPLICATION_PREFERRED_NAME 0x9F12)

(defn is-long-tag?[value]
  (= 0x1F (bit-and 0x1F value)))

(defn is-constructed?[value]
  (= 0x20 (bit-and 0x20 value)))

(defn is-primitive?[value]
  (not (is-constructed? value)))

(defn tag-class[tag]
  (condp = (bit-and 0xC0 tag)
    0x00 :universal
    0x40 :application
    0x80 :context-specific
    0xC0 :private))

(defn tag-is-constructed?[tag]
  (= 0x20 (bit-and 0x20 tag)))

(defn tag-has-second-value-byte?[tag]
  (= 0x1F (bit-and 0x1F tag)))

(defn is-last-optional-byte?[tag]
  (= 0x00 (bit-and 0x80 tag)))

(defn tag-value[tag]
  (bit-and 0x1F tag))

(defn optional-byte-tag-value[tag]
  (bit-and 0x7F tag))

(defn tag-length-bytes-count[first-byte]
  (cond
    (= 0x00 (bit-and 0x80 first-byte)) 1
    (= 0x81 first-byte) 2
    (= 0x82 first-byte) 3))

(defn tag-length-bytes-value[length-bytes]
  (let [first-byte (first length-bytes)
        count (tag-length-bytes-count first-byte)]
    (condp = count
      1 (bit-and 0x7F first-byte)
      2 (nth length-bytes 1)
      3 (combine-bytes (nth length-bytes 1) (nth length-bytes 2)))))

(defn parse-tlv-bytes[bytes]
  (if (< (count bytes) 3)
    nil
    (let [first-byte (first bytes)
          tag-value-byte-count (if (tag-has-second-value-byte? first-byte) 2 1)
          tag (if (= tag-value-byte-count 1)
            first-byte
            (combine-bytes (nth bytes 0) (nth bytes 1)))
          tag-class (tag-class first-byte)
          is-constructed (tag-is-constructed? first-byte)
          length-bytes (drop tag-value-byte-count bytes)
          length-bytes-count (tag-length-bytes-count (first length-bytes))
          length (tag-length-bytes-value length-bytes)
          v (take length (drop (+ tag-value-byte-count length-bytes-count) bytes))
          tail (drop length (drop (+ tag-value-byte-count length-bytes-count) bytes))]
      {:tag tag
        :class tag-class
        :is-constructed is-constructed
        :tag-length tag-value-byte-count
        :length length
        :value (vec v)
        :tail (vec tail)})))

(defn parse-full-tlv[bytes]
  (let [result (parse-tlv-bytes bytes)
        value (:value result)
        tail (:tail result)
        is-constructed (:is-constructed result)
        is-primitive (not is-constructed)
        is-empty-tail (empty? tail)
        is-not-empty-tail (not is-empty-tail)]
    (flatten (cond
      (and is-constructed is-not-empty-tail)
        (list result (parse-full-tlv value) (parse-full-tlv tail))
      (and is-constructed is-empty-tail)
        (list result (parse-full-tlv value))
      (and is-primitive is-not-empty-tail)
        (list result (parse-full-tlv tail))
      :else (list result)))))

(def status-bytes[
  ; Normal processing
  {:sw1 0x90 :sw2 0x00 :status "Process completed"}

  ; Warning processing
  {:sw1 0x62 :sw2 0x83 :status "State of non-volatile memory unchanged; selected file invalidated"}
  {:sw1 0x63 :sw2 0x00 :status "State of non-volatile memory changed; authentication failed"}

  ; Checking errors
  {:sw1 0x69 :sw2 0x83 :status "Command not allowed; authentication method blocked"}
  {:sw1 0x69 :sw2 0x84 :status "Command not allowed; referenced data invalidated"}
  {:sw1 0x69 :sw2 0x85 :status "Command not allowed; conditions of use not satisfied"}
  {:sw1 0x6A :sw2 0x81 :status "Wrong parameter(s) P1 P2; function not supported"}
  {:sw1 0x6A :sw2 0x82 :status "Wrong parameter(s) P1 P2; file not found"}
  {:sw1 0x6A :sw2 0x83 :status "Wrong parameter(s) P1 P2; record not found"}
  {:sw1 0x6A :sw2 0x88 :status "Referenced data (data objects) not found"}])

(defn status-bytes-to-description[sw1 sw2]
  (first (filter (fn [status] (and (= (:sw1 status) sw1) (= (:sw2 status) sw2)))  status-bytes)))

(defn from-bytes[source-byte source-byte-bits result result-keys]
  (let [key (first result-keys)]
    (if (empty? result-keys)
      result
      (from-bytes
        source-byte
        source-byte-bits
        (assoc result key (bit-on-at? (key source-byte-bits) source-byte))
        (rest result-keys)))))

(defn aip-from-bytes[byte1 byte2]
  (def aip-byte1-bits {
    :sda-supported 7
    :dda-supported 6
    :cardholder-verification-supported 5
    :terminal-risk-management-to-be-performed 4
    :issuer-authentication-supported 3
    :cda-supported 1})
  (def aip-byte2-bits {})
  (merge
   (from-bytes byte1 aip-byte1-bits {} (keys aip-byte1-bits))
   (from-bytes byte2 aip-byte2-bits {} (keys aip-byte2-bits))))

(defn afl-from-bytes[byte1 byte2 byte3 byte4]
  {:sfi (bit-shift-right byte1 3)
   :first-rec byte2
   :last-rec byte3
   :rec-count byte4})

(defn application-usage-control-from-bytes[byte1 byte2]
  (def byte1-bits {
    :domestic-cash 8
    :international-cash 7
    :domestic-goods 6
    :international-goods 5
    :domestic-services 4
    :international-services 3
    :atm 2
    :terminals-not-atm 1})
  (def byte2-bits {
    :domestic-cashback 8
    :international-cashback 7})
  (merge
    (from-bytes byte1 byte1-bits {} (keys byte1-bits))
    (from-bytes byte2 byte2-bits {} (keys byte2-bits))))

(defn cvm-list-from-bytes[byte1 byte2]
  (let [mask 2r00111111]
    (defn byte1-matches[ref]
      (equals-masked mask byte1 ref))
    { :fail-cardholder-verification-if-this-cvm-is-unsuccessful (bit-off-at? 7 byte1)
      :apply-succeeding-cv-rule-if-this-cvm-is-unsuccessful (bit-on-at? 7 byte1)
      :fail-cvm-processing (byte1-matches 2r00000000)
      :plaintext-pin-verification-performed-by-icc (byte1-matches 2r00000001)
      :enciphered-pin-verified-online (byte1-matches 2r00000010)
      :plaintext-pin-verification-performed-by-icc-and-signature-paper (byte1-matches 2r00000011)
      :enciphered-pin-verification-performed-by-icc (byte1-matches 2r00000100)
      :enciphered-pin-verification-performed-by-icc-and-signature-paper (bit-off-at? 6 byte1)
      :signature-paper (byte1-matches 2r00011110)
      :no-cvm-required (byte1-matches 2r00011111)
      :condition (condp = byte2
        0x00 :always
        0x01 :if-unattended-cash
        0x02 :if-not-unattended-cash-and-not-manual-cash-and-not-purchase-with-cashback
        0x03 :if-terminal-supports-the-cvm
        0x04 :if-manual-cash
        0x05 :if-purchase-with-cashback
        0x06 :if-transaction-is-in-the-application-currency-and-is-under-X-value
        0x07 :if-transaction-is-in-the-application-currency-and-is-over-X-value
        0x08 :if-transaction-is-in-the-application-currency-and-is-under-Y-value
        0x09 :if-transaction-is-in-the-application-currency-and-is-over-Y-value)}))

(defn tvr-from-bytes[byte1 byte2 byte3 byte4 byte5]
  (def byte1-bits {
    :offline-data-authentication-was-not-performed 8
    :sda-failed 7
    :icc-data-missing 6
    :card-appears-on-terminal-exception-file 5
    :dda-failed 4
    :cda-failed 3})

  (def byte2-bits {
    :icc-and-terminal-have-different-application-version 8
    :expired-application 7
    :application-not-yet-effective 6
    :requested-service-not-allowed-for-card-product 5
    :new-card 4})

  (def byte3-bits {
    :cardholder-verification-was-not-successful 8
    :unrecognised-cvm 7
    :pin-try-limit-exceeded 6
    :pin-entry-required-and-pin-pad-not-present-or-not-working 5
    :pin-entry-required-pin-pad-present-but-pin-was-not-entered 4
    :online-pin-entered 3})

  (def byte4-bits {
    :transaction-exceeds-floor-limit 8
    :lower-consecutive-offline-limit-exceeded 7
    :upper-consecutive-offline-limit-exceeded 6
    :transaction-selected-randomly-for-online-processing 5
    :merchant-forced-transaction-online 4})

  (def byte5-bits {
    :default-tdol-used 8
    :issuer-authentication-failed 7
    :script-processing-failed-before-final-generate-ac 6
    :script-processing-failed-after-final-generate-ac 5})

  (merge
    (from-bytes byte1 byte1-bits {} (keys byte1-bits))
    (from-bytes byte2 byte2-bits {} (keys byte2-bits))
    (from-bytes byte3 byte3-bits {} (keys byte3-bits))
    (from-bytes byte4 byte4-bits {} (keys byte4-bits))
    (from-bytes byte5 byte5-bits {} (keys byte5-bits))))

(defn filter-tag[tags tag-number]
  (first (filter #(= (:tag %) tag-number) tags)))

(defn get-tag[apdu tag-number]
  (let [data (:data apdu)
        tags (parse-full-tlv data)]
    (filter-tag tags tag-number)))

(defn tag-value-as-number[tag]
  (if (nil? tag)
    nil
    (hex-to-num (bytes-to-hex-string (:value tag)))))

(defn response-to-application[apdu]
  (defn- get-tag-value[tag-number]
    (let [tag (get-tag apdu tag-number)]
      (if (nil? tag)
        nil
        (:value tag))))

  (let [aid (get-tag-value APPLICATION_IDENTIFIER)
        label (get-tag-value APPLICATION_LABEL)
        preferred-name (get-tag-value APPLICATION_PREFERRED_NAME)]
    {:aid aid
     :rid (vec (take 5 aid))
     :label (bytes-to-ascii label)
     :priority (get-tag-value APPLICATION_PRIORITY_INDICATOR)
     :preferred-name (bytes-to-ascii preferred-name)}))

;; TODO: create the real PDOL based on the FCI template information, currently returns all zeros
(defn get-pdol[application-response]
  (let [pdol-tag (get-tag application-response PROCESSING_OPTIONS_DATA_OBJECT_LIST)]
    (if (nil? pdol-tag)
      [COMMAND_TEMPLATE 0x00]
      (into [] (concat [COMMAND_TEMPLATE (:length pdol-tag)] (repeat (:length pdol-tag) 0x00))))))

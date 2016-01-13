(ns clj-emv.dda
  "DDA parsing and validation"
  (:use clj-emv.crypto)
  (:use clj-emv.utils)
  (:use clj-emv.date)
  (:use clj-emv.tags)
  (:use clj-emv.file)
  (:use clj-emv.pcsc)
  (:require [clj-emv.ui :as ui])
  (:require [clj-time.core :as t])
  (:require [clj-time.coerce :as c]))

(defn parse-icc-public-key-certificate[certificate ni]
  (let [nic (nth certificate 19)
        modulus-field-length (- ni 42)]
    { :bytes certificate
      :length (count certificate)
      :recovered-data-header (nth certificate 0)
      :certificate-format (nth certificate 1)

      :application-pan (subvec certificate 2 12)
      :certificate-expiration-date (subvec certificate 12 14)
      :certificate-serial-number (subvec certificate 14 17)
      :hash-algorithm-indicator (nth certificate 17)

      :icc-public-key-algorithm-indicator (nth certificate 18)
      :icc-public-key-length nic
      :issuer-public-key-exponent-length (nth certificate 20)

      :icc-public-key (subvec certificate 21 (+ modulus-field-length 21))

      :hash-result (subvec certificate (+ modulus-field-length 21) (+ (+ modulus-field-length 21) 20))
      :recovered-data-trailer (nth certificate (+ (+ modulus-field-length 21) 20))}))

(defn validate-icc-public-key-certificate[certificate ni icc-public-key-remainder icc-public-key-exponent pan aip-bytes validate-expiration-date]
  (defn assert-field[field value] (assert (= (field certificate) value)))

  ; Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
  (assert-field :length ni)

  ; Step 2: The Recovered Data Trailer is equal to 'BC'
  (assert-field :recovered-data-trailer 0xBC)

  ; Step 3: The Recovered Data Header is equal to '6A'
  (assert-field :recovered-data-header 0x6A)

  ; Step 4: The Certificate Format is equal to '04'
  (assert-field :certificate-format 0x04)

  ; Step 5 implements the concatenation which is necessary to apply the hash algorithm in the next step.
  ; Step 6: Generate hash from concatenation
  ; Step 7: Compare recovered hash with generated hash
  (let [cert-bytes (subvec (:bytes certificate) 1 (- (:length certificate) 22))
        all (conj (into [] (concat cert-bytes icc-public-key-remainder)) icc-public-key-exponent)
        all-with-aip (into [] (concat all aip-bytes))
        ]
    ; TODO
    ;(assert-field :hash-result (sha1 all))
  )

  ; Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits
  (let [pan-string (hexify-list pan)
        padded-identifier-string (hexify-list (:application-pan certificate))
        identifier-string (clojure.string/replace padded-identifier-string #"F" "")]
    (assert (= pan-string identifier-string)))

  ; Step 9: Verify that the last day of the month specified in the Certification Expiration Date
  ; is equal to or later than today's date.
  (if validate-expiration-date
    (let [expiration-date
          (t/plus-
            (c/to-local-date
              (.withMaximumValue
                (.dayOfMonth
                  (parse-certificate-expiration-date (hexify-list (:certificate-expiration-date certificate))))))
            (t/days 1))
        today (t/today)]
      (assert (t/before? today expiration-date))))

  ; Step 10: Check the ICC Public Key Algorithm Indicator
  (assert-field :icc-public-key-algorithm-indicator 0x01)

  ; Step 11: Concatenate the Leftmost Digits of the ICC Public Key and the ICC Public Key Remainder (if present)
  ; to obtain the ICC Public Key Modulus
  (let [icc-public-key-modulus (if (> (:icc-public-key-length certificate) (count (:icc-public-key certificate)))
          (into [] (concat (:icc-public-key certificate) icc-public-key-remainder))
          (subvec (:icc-public-key certificate) 0 (:icc-public-key-length certificate)))]
    (assert (= (count icc-public-key-modulus) (:icc-public-key-length certificate)))
    icc-public-key-modulus))

(defn parse-sdad[sdad nic]
  (let [ldd (nth sdad 3)
        pad-pattern-start (+ 4 ldd)
        pad-pattern-length (- nic ldd 25)
        pad-pattern-end (+ pad-pattern-start pad-pattern-length)]
    { :bytes sdad
      :length (count sdad)
      :recovered-data-header (nth sdad 0)
      :signed-data-format (nth sdad 1)
      :hash-algorithm-indicator (nth sdad 2)
      :icc-dynamic-data-length ldd
      :icc-dynamic-data (subvec sdad 4 (+ 4 ldd))
      :pad-pattern (subvec sdad pad-pattern-start pad-pattern-end)
      :hash-result (subvec sdad pad-pattern-end (+ pad-pattern-end 20))
      :recovered-data-trailer (last sdad)}))


(defn validate-sdad[icc-public-key-modulus icc-public-key-exponent sdad ddol]
  (defn assert-field[field value] (assert (= (field sdad) value)))

  ; Step 1: SDAD and ICC Public Key Modulus have the same length
  (assert (= (count icc-public-key-modulus) (:length sdad)))

  ; Step 2: The Recovered Data Trailer is equal to 'BC'
  (assert-field :recovered-data-trailer 0xBC)

  ; Step 3: The Recovered Data Header is equal to '6A'
  (assert-field :recovered-data-header 0x6A)

  ; Step 4: The Signed Data Format is equal to '05'
  (assert-field :signed-data-format 0x05)

  ; Step 5: Concatenation of Signed Data Format, Hash Algorithm Indicator, ICC Dynamic Data Length,
  ; ICC Dynamic Data, Pad Pattern, random number
  ; Step 6: Genereate hash from concatenation
  ; Step 7: Compare recovered hash with generated hash
  (let [sdad-bytes (subvec (:bytes sdad) 1 (- (:length sdad) 21))
        all (into [] (concat sdad-bytes ddol))
        calculated-hash-result (sha1 all)]
    (assert-field :hash-result calculated-hash-result)))

(defn get-icc-public-key-certificate[issuer-public-key-modulus issuer-public-key-exponent ni tags]
  (let [signed-icc-public-key-certificate (:value (filter-tag tags ICC_PUBLIC_KEY_CERTIFICATE))
        public-key-certificate-bytes (recover signed-icc-public-key-certificate issuer-public-key-exponent issuer-public-key-modulus)
        icc-public-key-certificate (parse-icc-public-key-certificate public-key-certificate-bytes ni)]
    icc-public-key-certificate))

(defn get-validated-icc-public-key-modulus[icc-public-key-certificate ni tags aip-bytes validate-expiration-date]
  (let [nic (:icc-public-key-length icc-public-key-certificate)
        icc-public-key-exponent (tag-value-as-number (filter-tag tags ICC_PUBLIC_KEY_EXPONENT))
        icc-public-key-modulus (validate-icc-public-key-certificate
          icc-public-key-certificate
          ni
          (:value (filter-tag tags ICC_PUBLIC_KEY_REMAINDER))
          icc-public-key-exponent
          (:value (filter-tag tags APPLICATION_PRIMARY_ACCOUNT_NUMBER))
          aip-bytes
          validate-expiration-date)]
    [icc-public-key-modulus icc-public-key-exponent nic]))

(defn perform-dda[channel icc-public-key-modulus icc-public-key-exponent nic]
  (let [random-numbers (repeatedly 4 #(rand-int 255))
        response (internal-authenticate-command channel (byte-array random-numbers))
        data (:data response)
        dda-tags (parse-full-tlv data)

        signed-sdad (:value (filter-tag dda-tags SIGNED_DYNAMIC_APPLICATION_DATA))
        sdad-bytes (recover signed-sdad icc-public-key-exponent icc-public-key-modulus)
        sdad (parse-sdad sdad-bytes nic)
        res (validate-sdad icc-public-key-modulus icc-public-key-exponent sdad random-numbers)]
    (dorun (ui/println-with-stars "DDA: Verification of Signed Dynamic Application Data (SDAD) succcessful"))))

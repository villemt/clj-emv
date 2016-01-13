(ns clj-emv.sda
  "SDA parsing and validation"
  (:use clj-emv.crypto)
  (:use clj-emv.utils)
  (:use clj-emv.date)
  (:use clj-emv.tags)
  (:use clj-emv.file)
  (:require [clj-emv.ui :as ui])
  (:require [clj-time.core :as t])
  (:require [clj-time.coerce :as c]))

(defn parse-issuer-public-key-certificate[certificate nca]
  (let [ni (nth certificate 13)
        modulus-field-length (- nca 36)]

    ;If NI <= NCA - 36, consists of the full Issuer Public Key padded to the right with NCA - 36- NI bytes of value 'BB'. If NI > NCA - 36, consists of the NCA - 36 most significant bytes of the Issuer Public Key
    (assert (> ni (- nca 36))) ; TODO: implement the padded option

    { :bytes certificate
      :length (count certificate)
      :recovered-data-header (nth certificate 0)
      :certificate-format (nth certificate 1)
      :issuer-identifier (subvec certificate 2 6)
      :certificate-expiration-date (subvec certificate 6 8)
      :certificate-serial-number (subvec certificate 8 11)
      :hash-algorithm-indicator (nth certificate 11)
      :issuer-public-key-algorithm-indicator (nth certificate 12)
      :issuer-public-key-length ni
      :issuer-public-key-exponent-length (nth certificate 14)
      :issuer-public-key (subvec certificate 15 (+ modulus-field-length 15))
      :hash-result (subvec certificate (+ modulus-field-length 15) (+ (+ modulus-field-length 15) 20))
      :recovered-data-trailer (nth certificate (+ (+ modulus-field-length 15) 20))}))

(defn validate-issuer-public-key-certificate[certificate nca issuer-public-key-remainder issuer-public-key-exponent pan validate-expiration-date]
  (defn assert-sda-field[field value] (assert (= (field certificate) value)))

  ; Step 1: If the Issuer Public Key Certificate has a length different from the length of the
  ; Certification Authority Public Key Modulus obtained in the previous section, SDA has failed.
  (assert-sda-field :length nca)

  ; Step 2: In order to obtain the recovered data specified in Table 6, apply the recovery function
  ; specified in Annex A2.1 to the Issuer Public Key Certificate using the Certification Authority Public Key
  ; in conjunction with the corresponding algorithm. If the Recovered Data Trailer is not equal to 'BC', SDA has failed.
  (assert-sda-field :recovered-data-trailer 0xBC)

  ; Step 3: Check the Recovered Data Header. If it is not '6A', SDA has failed.
  (assert-sda-field :recovered-data-header 0x6A)

  ; Step 4: Check the Certificate Format. If it is not '02', SDA has failed.
  (assert-sda-field :certificate-format 0x02)

  ; Step 5: Concatenate from left to right the second to the tenth data elements in Table 6 (that is,
  ; Certificate Format through Issuer Public Key or Leftmost Digits of the Issuer Public Key), followed
  ; by the Issuer Public Key Remainder (if present), and finally the Issuer Public Key Exponent.
  ;
  ; Step 6: Apply the indicated hash algorithm (derived from the Hash Algorithm Indicator) to the result
  ; of the concatenation of the previous step to produce the hash result.
  ;
  ; Step 7: Compare the calculated hash result from the previous step with the recovered Hash Result.
  ; If they are not the same, SDA has failed.
  (let [cert-bytes (subvec (:bytes certificate) 1 (- (:length certificate) 21))
        all (conj (into [] (concat cert-bytes issuer-public-key-remainder)) issuer-public-key-exponent)]
    (assert-sda-field :hash-result (sha1 all))
  )

  ; Step 8:Verify that the Issuer Identifier matches the leftmost 3-8 PAN digits (allowing for the possible
  ; padding of the Issuer Identifier with hexadecimal 'F's). If not, SDA has failed.
  (let [padded-identifier-string (hexify-list (:issuer-identifier certificate))
        identifier-string (clojure.string/replace padded-identifier-string #"F" "")
        pan-string (hexify-list (subvec pan 0 (/ (count identifier-string) 2)))]
    (assert (= pan-string identifier-string)))

  ; Step 9: Verify that the last day of the month specified in the Certificate Expiration Date is equal to
  ; or later than today’s date. If the Certificate Expiration Date is earlier than today’s date,
  ; the certificate has expired, in which case SDA has failed.
  (if validate-expiration-date
    (let [expiration-date
            (t/plus-
              (c/to-local-date
                (.withMaximumValue
                  (.dayOfMonth
                    (parse-certificate-expiration-date (hexify-list (:certificate-expiration-date certificate))))))
              (t/days 1))
          today (t/today)]
      (assert (t/before? today expiration-date))
    ))

  ; Step 10: Verify that the concatenation of RID, Certification Authority Public Key Index, and Certificate
  ; Serial Number is valid. If not, SDA has failed. This step is optional and is to allow the revocation
  ; of the Issuer Public Key Certificate against a Certification Revocation List that may be kept by the terminal

  ; TODO: Implement revocation list

  ; Step 11: If the Issuer Public Key Algorithm Indicator is not recognised, SDA has failed.
  (assert-sda-field :issuer-public-key-algorithm-indicator 0x01)

  ; Step 12: If all the checks above are correct, concatenate the Leftmost Digits of the Issuer Public Key and
  ; the Issuer Public Key Remainder (if present) to obtain the Issuer Public Key Modulus, and continue with
  ; the next steps for the verification of the Signed Static Application Data.
  (let [issuer-public-key-modulus (concat (:issuer-public-key certificate) issuer-public-key-remainder)]
    ; Check that the created key length matches the value in the certicate
    (assert (= (count issuer-public-key-modulus) (:issuer-public-key-length certificate)))
    (into [] issuer-public-key-modulus)))

(defn parse-ssad[ssad ni]
  { :bytes ssad
    :length (count ssad)
    :recovered-data-header (nth ssad 0)
    :signed-data-format (nth ssad 1)
    :hash-algorithm-indicator (nth ssad 2)
    :data-authentication-code (subvec ssad 3 5)
    :pad-pattern (subvec ssad 5 (+ (- ni 26) 5))
    :hash-result (subvec ssad (+ (- ni 26) 5) (+ (+ (- ni 26) 5) 20))
    :recovered-data-trailer (last ssad)})

(defn validate-ssad[issuer-public-key-modulus issuer-public-key-exponent ssad]
  (defn assert-sda-field[field value] (assert (= (field ssad) value)))

  ; Step 1: Signed Static Application Data and Issuer Public Key Modulus have the same length
  (assert (= (count issuer-public-key-modulus) (:length ssad)))

  ; Step 2: The Recovered Data Trailer is equal to 'BC'
  (assert-sda-field :recovered-data-trailer 0xBC)

  ; Step 3: The Recovered Data Header is equal to '6A'
  (assert-sda-field :recovered-data-header 0x6A)


  ; Step 4: The Signed Data Format is equal to '03'
  (assert-sda-field :signed-data-format 0x03)

  ; Step 5: Concatenation of Signed Data Format, Hash Algorithm Indicator, Data Authentication Code,
  ; Pad Pattern, the data listed by the AFL and finally the SDA Tag List
  ;
  ; Step 6: Generate hash from concatenation
  ;
  ; Step 7: Compare recovered hash with generated hash. Store the Data Authentication Code from SSAD in tag '9F45'

  ; TODO

  (:data-authentication-code ssad))

(defn get-issuer-public-key-certificate[application tags]
  (let [aid (:aid application)
        rid (:rid application)
        key-index (tag-value-as-number (filter-tag tags CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX))
        ca-public-key-info (find-key key-index rid)
        ca-public-key-modulus (:modulus ca-public-key-info)
        ca-public-key-exponent (:exponent ca-public-key-info)
        nca (:nca ca-public-key-info)
        signed-issuer-public-key-certificate (:value (filter-tag tags ISSUER_PUBLIC_KEY_CERTIFICATE))
        public-key-certificate-bytes (recover signed-issuer-public-key-certificate ca-public-key-exponent ca-public-key-modulus)
        issuer-public-key-certificate (parse-issuer-public-key-certificate public-key-certificate-bytes nca)
        ]
  [issuer-public-key-certificate nca]))


(defn get-validated-issuer-public-key-modulus[issuer-public-key-certificate nca tags validate-expiration-date]
  (let [ni (:issuer-public-key-length issuer-public-key-certificate)
        issuer-public-key-exponent (tag-value-as-number (filter-tag tags ISSUER_PUBLIC_KEY_EXPONENT))
        issuer-public-key-modulus (validate-issuer-public-key-certificate
          issuer-public-key-certificate
          nca
          (:value (filter-tag tags ISSUER_PUBLIC_KEY_REMAINDER))
          issuer-public-key-exponent
          (:value (filter-tag tags APPLICATION_PRIMARY_ACCOUNT_NUMBER))
          validate-expiration-date)]
    [issuer-public-key-modulus issuer-public-key-exponent ni]))

(defn get-validated-data-authentication-code[issuer-public-key-modulus issuer-public-key-exponent ni tags]
  (let [signed-ssad (:value (filter-tag tags SIGNED_APPLICATION_DATA))
        ssad-bytes (recover signed-ssad issuer-public-key-exponent issuer-public-key-modulus)
        ssad (parse-ssad ssad-bytes ni)
        data-authentication-code (validate-ssad issuer-public-key-modulus issuer-public-key-exponent ssad)]
    data-authentication-code))


(defn perform-sda[issuer-public-key-modulus issuer-public-key-exponent ni tags]
  (let [data-authentication-code (get-validated-data-authentication-code issuer-public-key-modulus issuer-public-key-exponent ni tags)]
    (dorun (ui/println-with-stars "SDA: Verification of Signed Static Application Data (SSAD) succcessful"))
    data-authentication-code))

(ns clj-emv.pcsc
  "PC/SC related smart card reader functionality"
  (:require [clj-emv.bit-ops :as bit-ops])
  (:import (javax.smartcardio TerminalFactory CommandAPDU)))

; remove
(defn hexify-old[value]
  (format "%02X" value))

(defn get-terminals[]
  (defn get-factory[] (TerminalFactory/getDefault))

  (defn my-terminal[terminal]
    {:is-card-present (.isCardPresent terminal)
     :name (.getName terminal)
     :instance terminal})

  (let [terminals (seq (.list (.terminals (get-factory))))
        my-terminals (map my-terminal terminals)]
    my-terminals))

(defn get-card[terminal]
  (let [instance (.connect (:instance terminal) "*")
        atr (.getATR instance)]
    {:instance instance
     :protocol (.getProtocol instance)}))

(defn get-channel[card]
  (let [instance (.getBasicChannel (:instance card))
        number (.getChannelNumber instance)]
    {:instance instance
     :number number}))

(defn response-apdu[response]
  {:number (.getNr response)
   :bytes (vec (map bit-ops/unsigned (.getBytes response)))
   :data (vec (map bit-ops/unsigned (.getData response)))
   :sw1 (.getSW1 response)
   :sw2 (.getSW2 response)
   :success (and (= (.getSW1 response) 0x90) (= (.getSW2 response) 0x00))})

(defn transmit[channel apdu]
  (response-apdu (.transmit (:instance channel) apdu)))

(defn select-command[channel aid]
  (transmit channel (CommandAPDU. 0x00 0xA4 0x04 0x00 (byte-array aid))))

;; The last magic number 100 as the length is needed due to the strange behavior of javax.smartcardio
(defn read-record-command[channel sfi rec]
  (transmit channel (CommandAPDU. 0x00 0xB2 (int rec) (bit-or (bit-shift-left sfi 3) 4) 100)))

(defn get-processing-options-command[channel pdol]
  (transmit channel (CommandAPDU. 0x80 0xA8 0x00 0x00 (byte-array pdol))))

(defn get-data-command[channel p1 p2]
  (transmit channel (CommandAPDU. 0x80 0xCA p1 p2)))

(defn generate-ac-command[channel p1 data]
  (transmit channel (CommandAPDU. 0x80 0xAE p1 0x00 data)))

(defn get-dynamic-number-command[channel]
  (transmit channel (CommandAPDU. 0x00 0x84 0x00 0x00)))

(defn verify-command[channel p2 data]
  (transmit channel (CommandAPDU. 0x00 0x20 0x00 p2 data)))

(defn internal-authenticate-command[channel data]
  (transmit channel (CommandAPDU. 0x00 0x88 0x00 0x00 data)))

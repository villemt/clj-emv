(ns clj-emv.terminal
  "Terminal resident data")

(def TERMINAL_APPLICATION_VERSION_NUMBER 0x02)

(def TERMINAL_TYPE 0x9F35)

(def terminal-resident-tags
  {;Terminal Country Code, Finland
   0x9F1A [0x00 0xF6]

   ;Transaction Currency Code, EUR
   0x5F2A [0x03 0xD2]

   ;Transaction Type
   0x9C [0x21]

   ;Terminal Type
   0x9F35 [0x11]

   ;Unpredictable number (random)
   0x9F37 (vec (repeatedly 4 #(rand-int 255)))
  })


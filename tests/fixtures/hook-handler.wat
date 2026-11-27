;; A minimal component that returns an empty success string.
(component
  (core module $guest
    (memory (export "memory") 1)
    (func (export "allocate") (param i32 i32 i32 i32) (result i32)
      i32.const 16)
    (func (export "run") (param i32 i32) (result i32)
      i32.const 0))
  (core instance $guest (instantiate $guest))
  (type $output (result string (error string)))
  (type $signature (func (param "event" string) (result $output)))
  (func $handle (type $signature)
    (canon lift (core func $guest "run") (memory (core memory $guest "memory")) (realloc (core func $guest "allocate"))))
  (instance $api (export "handle" (func $handle)))
  (export "pyloros:hooks/handler@1.0.0" (instance $api)))

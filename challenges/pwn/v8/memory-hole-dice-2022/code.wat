(module
   (global $g (import "js" "global") (mut i64))
   (func (export "getGlobal") (result i64)
        (global.get $g))
   (func (export "incGlobal")
        (global.set $g
            (i64.add (global.get $g) (i64.const 1))))
   (func (export "setGlobal") (param $p1 i64)
        (global.set $g (local.get $p1)))
)

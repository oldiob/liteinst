(use-modules
 ((gnu packages cpp) #:select (asmjit))
 (guix packages)
 (guix profiles)
 (guix transformations))

(define (without-tests pkg)
  ((options->transformation
    `((without-tests . ,(package-name pkg))))
   pkg))

(manifest
 (cons*
  (package->manifest-entry
   (without-tests asmjit))
  (manifest-entries
   (specifications->manifest
    (list
     "gdb"
     "gcc-toolchain"
     "coreutils"
     "findutils"
     "gawk"
     "grep"
     "less"
     "make"
     "pkg-config"
     "sed")))))

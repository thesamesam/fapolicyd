AC_DEFUN([LD_SO_PATH],
[
  bash_path=`command -v bash`
  xpath1=`readelf -e $bash_path | grep Requesting | sed 's/.$//' | rev | cut -d" " -f1 | rev`
  xpath=`realpath $xpath1`
  if test ! -f "$xpath" ; then
    AC_MSG_ERROR([Cant find the dynamic linker])
  fi
  echo "dynamic linker is.....$xpath"
  AC_DEFINE_UNQUOTED(SYSTEM_LD_SO, ["$xpath"], [dynamic linker])
])

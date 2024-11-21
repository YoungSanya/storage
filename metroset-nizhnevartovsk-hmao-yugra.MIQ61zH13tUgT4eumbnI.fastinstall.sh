#!/usr/bin/env bash

script_version="2.8.3"
cloud_code="2LfCnF0HgGm8WumGVXpX"
lic_token="MIQ61zH13tUgT4eumbnI"
engineer_mode=0
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# LOGFILE=$SCRIPT_DIR/fastinstall.log
# INSTALL_PROCESS_FILE=$SCRIPT_DIR/install.cfg
min_disk_space=4
min_num_cores=2
min_ram=2
min_os_version=8
# threads=$(nproc)
# service_name="fastinstall"
# service="/etc/systemd/system/$service_name.service"
CentOsVersion=0
IsCentosStream=0
IsVEOS=0
mode="interactive"
total_bridges_speed=0
disable_interfaces_check=0
disable_hyper_threading_check=0
use_only_valid_interfaces=1
bypass_available=0
declare -A interface_list=()
declare -A interface_names=()
declare -A interface_ips=()

declare -A bonded_devices=()
declare -A interfaces=()
declare -A in_dev=()
declare -A out_dev=()
declare in_dev_config=()
declare ou_dev_config=()
declare bridges=()

declare available_interfaces=()

declare -A interfaces_speeds=()

# dpi_installed=$(rpm -qa | grep fastdpi | wc -l)
# qoe_installed=$(rpm -qa | grep fastor | wc -l)
# dpiui2_installed=$(rpm -qa | grep dpiui2 | wc -l)
# network_manager_installed=$(rpm -qa | grep NetworkManager | wc -l)

# sig_local_file=$SCRIPT_DIR/fastdpi.sig
# lic_local_file=$SCRIPT_DIR/fastdpi.lic
# conf_local_file=$SCRIPT_DIR/fastdpi.conf
# lic_resp_file=$SCRIPT_DIR/lic_response_file.txt

SAVE_IFS="$IFS"

function YesNoHandler()
{
  local msg="${1}"
  local default_value="${2}"
  local val=""
  while read -p "$msg" v; do
    if [ -z "$v" ]; then
      v="${default_value}"
    fi
    case $v in
      [Yy]*)
        val="y"
        ;;
      [Nn]*)
        val="n"
        ;;
      *)
        msg="Incorrect answer! ${1}"
        ;;
    esac
    if [ ! -z "$val" ]; then
      break
    fi
  done

  echo "${val}"
}

function RemoveExtraSpaces()
{
  local string="${1}"

  local n_string=$(echo "$string" | xargs)
#  n_string=${n_string%% }
#  n_string=${n_string## }

  echo "$n_string"
}

function CalculateTotalInterfacesSpeed()
{
  local string="${1}"
  local operator="${2}"

  local value="${string//[^0-9]/ }"
  value=$(($value/1000))

  if [ $operator == "add" ];then
    total_bridges_speed=$(($total_bridges_speed + $value))
  else
    total_bridges_speed=$(($total_bridges_speed - $value))
  fi
}

function InitGlobalVariables()
{
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
  LOGFILE=$SCRIPT_DIR/fastinstall.log
  INSTALL_PROCESS_FILE=$SCRIPT_DIR/install.cfg
  threads=$(nproc)
  service_name="fastinstall"
  service="/etc/systemd/system/$service_name.service"
  CentOsVersion=0
  mode=""

  UpdateDpiui2Installed
  UpdateQoEInstalled
  UpdateDpiInstalled

  network_manager_installed=$(rpm -qa | grep NetworkManager | wc -l)

  sig_local_file=$SCRIPT_DIR/fastdpi.sig
  lic_local_file=$SCRIPT_DIR/fastdpi.lic
  conf_local_file=$SCRIPT_DIR/fastdpi.conf
  lic_resp_file=$SCRIPT_DIR/lic_response_file.txt

  total_bridges_speed=0

  available_interfaces=("82540" "82545" "82546" "82571" "82572" "82573" "82574" "82583" "ICH8" "ICH9" "ICH10" "PCH" "PCH2" "I217" "I218" "I219" "82573" "82576" "82580" "I210" "I211" "I350" "I354" "DH89" "I225" "82598" "82599" "X520" "X540" "X550" "X710" "XL710" "X722" "XXV710" "Mellanox ConnectX-5 Ex" "mlx5" "VMXNET3" "Intel E810" "E810")
}

function EngineerExit()
{
  if [ "$engineer_mode" == 1 ];then
    local q="Do you want to exit? [y/N](No is default) "
    dis=$(YesNoHandler "$q" "n")
    case $dis in
      [Yy]*)
        exit
    ;;
    esac
  else
    exit
  fi
}

function UpdateDpiInstalled()
{
  dpi_installed=$(rpm -qa | grep fastdpi | wc -l)
}

function UpdateQoEInstalled()
{
  qoe_installed=$(rpm -qa | grep fastor | wc -l)
}

function UpdateDpiui2Installed()
{
  dpiui2_installed=$(rpm -qa | grep dpiui2 | wc -l)
}

#HELPER FUNCTIONS
function print_info() {
  echo -e "\033[1m info:   \033[0m $@ "
}

function print_ok() {
  echo -e "\033[1m done:  \033[0m \033[32m $@ \033[0m"
}

function print_error() {
  echo -e "\033[1m ERROR:\033[0m \033[31m $@\033[0m"
}

function print_spaces() {
  local num="${1}"
  local str="${2}"

  for ((i = 0; i <= num; i++)); do
    str=" "$str" "
  done

  echo "$str"
}

function print_error_box() {
  local s=("$@") b w
  for l in "${s[@]}"; do
    ((w < ${#l})) && {
      b="$l"
      w="${#l}"
    }
  done
  tput setaf 7
  echo " -${b//?/-}-
| ${b//?/ } |"
  for l in "${s[@]}"; do
    printf '| %s%*s%s |\n' "$(tput setaf 1)" "-$w" "$l" "$(tput setaf 7)"
  done
  echo "| ${b//?/ } |
 -${b//?/-}-"
  tput sgr 0
}

function print_box() {
  local s=("$@") b w
  for l in "${s[@]}"; do
    ((w < ${#l})) && {
      b="$l"
      w="${#l}"
    }
  done
  #  tput setaf 7
  echo " -${b//?/-}-
| ${b//?/ } |"
  for l in "${s[@]}"; do
    printf '| %*s |\n' "-$w" "$l"
    #    printf '| %s%*s%s |\n' "$(tput setaf 4)" "-$w" "$l" "$(tput setaf 3)"
  done
  echo "| ${b//?/ } |
 -${b//?/-}-"
  tput sgr 0
}

function print_box_without_borders_y() {
  local s=("$@") b w
  for l in "${s[@]}"; do
    ((w < ${#l})) && {
      b="$l"
      w="${#l}"
    }
  done
  #  tput setaf 7
  echo " -${b//?/-}-
  ${b//?/ }  "
  for l in "${s[@]}"; do
    printf '  %*s  \n' "-$w" "$l"
    #    printf '| %s%*s%s |\n' "$(tput setaf 4)" "-$w" "$l" "$(tput setaf 3)"
  done
  echo "  ${b//?/ }
 -${b//?/-}-"
  tput sgr 0
}

function WriteLog() {
  local logMessage=$1
  local logPriority=$2

  #check if level exists
  # [[ ${LOG_LEVELS[$logPriority]} ]] || return 1

  #check if level is enough
  # (( ${LOG_LEVELS[$logPriority]} < ${LOG_LEVELS[$SCRIPT_LOG_LEVEL]} )) && return 2

  echo "[$(date +%F) $(date +%T)][${logPriority}]: ${logMessage}" >>"$LOGFILE"
}

function CheckInternetConnection() {
  local urls=("google.com" "yandex.ru" "cloud.vasexperts.ru")

  for url in "${urls[@]}"; do
    local status=$(ping -q -c1 "${url}" &>/dev/null && echo online || echo offline)

    if [ "${status}" == "offline" ]; then
      print_error_box "No internet connection!"
      WriteLog "No internet connection!" "Error"
      EngineerExit
    fi
  done

}

function InSubnet() {
  local ip ip_a mask netmask sub sub_ip rval start end

  # Define bitmask.
  local readonly BITMASK=0xFFFFFFFF

  # Set DEBUG status if not already defined in the script.
  [[ "${DEBUG}" == "" ]] && DEBUG=0

  # Read arguments.
  IFS=/ read sub mask <<<"${1}"
  IFS=. read -a sub_ip <<<"${sub}"
  IFS=. read -a ip_a <<<"${2}"

  # Calculate netmask.
  netmask=$(($BITMASK << $((32 - $mask)) & $BITMASK))

  # Determine address range.
  start=0
  for o in "${sub_ip[@]}"; do
    start=$(($start << 8 | $o))
  done

  start=$(($start & $netmask))
  end=$(($start | ~$netmask & $BITMASK))

  # Convert IP address to 32-bit number.
  ip=0
  for o in "${ip_a[@]}"; do
    ip=$(($ip << 8 | $o))
  done

  # Determine if IP in range.
  (($ip >= $start)) && (($ip <= $end)) && rval=1 || rval=0

  (($DEBUG)) &&
    printf "ip=0x%08X; start=0x%08X; end=0x%08X; in_subnet=%u\n" $ip $start $end $rval 1>&2

  echo "${rval}"
}

function ConvertDevNameForConfig() {
  local dev_name="${1}"
  local ptr="0000:"
  local replace=""
  str="${dev_name/$ptr/$replace}"
  str="${str/:/-}"

  echo $str
}

function GetArrayIndex() {
  local val="${1}"
  local arr=("$@")

  echo "Value is $val"
  echo "Finding:"
  for i in "${!arr[@]}"; do
    echo "$i ${arr[$i]}"
    if [[ "${arr[$i]}" = "$val" ]]; then
      echo "Found $i"
      break
    fi
  done
}

function InstallNetTools() {

  WriteLog "Install NetTools START" "DEBUG"
  if [ $CentOsVersion -ge 8 ]; then
    dnf install -y net-tools
  else
    yum install -y net-tools
  fi
  WriteLog "Install NetTools FINISH" "DEBUG"
}

function TestVersion() {
  local versionStr=$1

  for versionNum in {6..10}; do
    if [[ $CENTOSRELEASE == *"${versionStr} ${versionNum}"* ]]; then
      CentOsVersion=$versionNum
    fi
  done

  if [[ $CENTOSRELEASE == *"Stream"* ]]; then
    IsCentosStream=1
  fi

  if [[ $OsRelease == *"VEOS"* ]]; then
      IsVEOS=1
  fi
}

function InstallProcessFileEdit() {
  # local file=/var/fastinstall/test.conf
  local prop=$1
  local val=$2

  if [ ! -f $INSTALL_PROCESS_FILE ]; then
    touch $INSTALL_PROCESS_FILE
  fi

  prop_exists=$(cat "$INSTALL_PROCESS_FILE" | grep $prop | wc -l)
  if [[ $prop_exists -ne 0 ]]; then
    ptr="^\(${prop}\s*=\s*\).*$"
    rplc="\1${val}"
    sed -i "s,${ptr},${rplc},g" $INSTALL_PROCESS_FILE
  else
    echo "${prop}=${val}" >>$INSTALL_PROCESS_FILE
  fi
}

function GetInstallProcessProperty() {
  local prop=$1

  if [ ! -f $INSTALL_PROCESS_FILE ]; then
    return
  fi

  prop_line=$(cat "$INSTALL_PROCESS_FILE" | grep $prop)

  if [[ -z $prop_line ]]; then
    return
  fi
  prop="${prop}="
  echo "${prop_line/$prop/''}"
}

function EditEnvFile() {
  local prop=$1
  local val=$2
  local file=$3

  if [ ! -f $file ]; then
    touch $file
  fi

  prop_exists=$(cat "$file" | grep $prop | wc -l)
  if [[ $prop_exists -ne 0 ]]; then
    ptr="^\(${prop}\s*=\s*\).*$"
    rplc="\1${val}"
    sed -i "s,${ptr},${rplc},g" $file
  else
    echo $'\n'"${prop}=${val}" >>$file
  fi
}

function EditConfig() {
  # local file=/var/fastinstall/test.conf
  local file=/etc/dpi/fastdpi.conf
  local prop=$1
  local val=$2

  if [ ! -f $file ]; then
    touch $file
  fi

  prop_exists=$(cat "$file" | grep $prop | wc -l)
  if [[ $prop_exists -ne 0 ]]; then
    ptr="^\(${prop}\s*=\s*\).*$"
    rplc="\1${val}"
    sed -i "s,${ptr},${rplc},g" $file
  else
    echo $'\n'"${prop}=${val}" >>$file
  fi
}

function EditGRUB() {
  sed -c -i "s/\($1 *= *\).*/\1$2/" $GRUB_CMDLINE_LINUX
}

function RevertGrub()
{
  print_info "Revert grub START"
  WriteLog "Revert grub START" "DEBUG"

  local file=/etc/default/grub

  local localfile=$SCRIPT_DIR/grub

  if [ ! -f "$localfile" ]; then
    print_error "Can't find default grub file ( ${localfile} doesn't exists)!"
    WriteLog "Can't find default grub file ( ${localfile} doesn't exists)!" "ERROR"
  else
    mv -f "${localfile}" "${file}"
    grub2-mkconfig -o /boot/grub2/grub.cfg
  fi

  print_info "Revert grub FINISH"
  WriteLog "Revert grub FINISH" "DEBUG"
}

function EditCore() {
  print_info "EDIT CORE START"
  WriteLog "EDIT CORE START" "DEBUG"
  #Edit GRUB
  file=/etc/default/grub

  localfile=$SCRIPT_DIR/grub

  if [ ! -f "$localfile" ]; then
    cp $file $localfile
  fi

  grub=$(cat $localfile | grep GRUB_CMDLINE_LINUX)

  WriteLog "grub config ${grub}" "DEBUG"
  prefix="GRUB_CMDLINE_LINUX="
  grub=${grub#"$prefix"}
  grub="${grub:1:-1}"
  cr=$(grep -q pdpe1gb /proc/cpuinfo && echo "1GB OK")

  WriteLog "cr value is ${cr}" "DEBUG"
  if [ "$cr" = "1GB OK" ]; then
    hugepagesz="1G"
    hugepages=8
  else
    hugepagesz="2M"
    hugepages=512
  fi

  spectre="off"

  cores=$(lscpu | grep "NUMA node0 CPU(s):" | awk '{print $4}')
  cores_per_socket=$(lscpu | grep "Core(s) per socket:" | awk '{print $4}')

  local cores_arr=()
  if [[ $cores == *","* ]]; then
    SAVE_IFS="$IFS"
    IFS=","
    read -r -a arr <<<"$cores"
    for el in "${arr[@]}"; do
      if [[ $el == *"-"* ]]; then
        IFS="-"
        read -r core_min core_max <<<"$el"
        for ((i = $core_min; i <= $core_max; i++)); do
          cores_arr+=("${i}")
        done
      else
        cores_arr+=("${el}")
      fi
    done
    IFS="$SAVE_IFS"
  elif [[ $cores == *"-"* ]]; then
    SAVE_IFS="$IFS"
    IFS="-"
    read -r core_min core_max <<<"$cores"
    for ((i = $core_min; i <= $core_max; i++)); do
      cores_arr+=("${i}")
    done
    IFS="$SAVE_IFS"
  else
    cores_arr+=("${cores}")
  fi

  local cores_length="${#cores_arr[@]}"
  if [ $(($cores_length%2)) == 1 ];then
    cores_length=$(($cores_length - 1))
  fi

  if [ $cores_per_socket -lt $cores_length ];then
    cores_length=$cores_per_socket
    local cr_arr=()

    for ((i = 0; i < $cores_per_socket; i++)); do
      cr_arr+=("${cores_arr[$i]}")
    done

    cores_arr=()
    for i in ${cr_arr[@]}; do
      cores_arr+=("${i}")
    done
  fi


  declare box_arr=()



  msg="Available cores num is ${cores_length}."
  box_arr+=("${msg}")
  WriteLog "${msg}" "DEBUG"
#  if [ $cores_length == 4 ];then
#    msg="[WARNING] Available cores num is ${cores_length}. It is not enough."
#    box_arr+=("${msg}")
#    WriteLog "${msg}" "DEBUG"
#  else
#    msg="Available cores num is ${cores_length}."
#    box_arr+=("${msg}")
#    WriteLog "${msg}" "DEBUG"
#  fi

  local disp_threads_need=0
  local service_threads_need=1

  local num_threads_by_speed=0
  if [ $total_bridges_speed -lt 4 ];then
    num_threads_by_speed=2
  elif [ $total_bridges_speed -lt 11 ];then
    num_threads_by_speed=4
  elif [ $total_bridges_speed -lt 26 ];then
    num_threads_by_speed=8
  elif [ $total_bridges_speed -lt 57 ];then
    num_threads_by_speed=16
  else
    num_threads_by_speed=32
  fi

  msg="Recommended threads number for selected bridges is ${num_threads_by_speed}."
  box_arr+=("${msg}")
  WriteLog "${msg}" "DEBUG"
  disp_threads_need=1
  local dpdk_engine_cfg=$(cat /etc/dpi/fastdpi.conf | grep "dpdk_engine=")
  if [ -z "${dpdk_engine_cfg}" ];then
    disp_threads_need=1
  else
    dpdk_engine_cfg=${dpdk_engine_cfg#"dpdk_engine="}
    case $dpdk_engine_cfg in
    0)
      disp_threads_need=1
      ;;
    1)
      disp_threads_need=2
      ;;
    2)
      local rss_cfg=$(cat /etc/dpi/fastdpi.conf | grep "dpdk_rss=")
      local rss_val=2
      if [ ! -z "${rss_cfg}" ]; then
        local rss=${rss_cfg#"rss_cfg="}

        local re='^[0-9]+$'
        if [[ $rss =~ $re ]]; then
          rss_val=${rss}
        fi
      fi

      disp_threads_need=$(("${rss_val}" * 2))
      ;;
    3)
      disp_threads_need="${#bridges[@]}"
      ;;
    4)
      disp_threads_need=$(("${#bridges[@]}" * 2))
      ;;
    *)
      disp_threads_need=1
      ;;
    esac
  fi


  msg="Recommended dispatcher threads number for current dpdk_engine is ${disp_threads_need}."
  box_arr+=("${msg}")
  WriteLog "${msg}" "DEBUG"
  msg="Recommended service threads number  is 1."
  box_arr+=("${msg}")
  WriteLog "${msg}" "DEBUG"

  box_arr+=("")
  box_arr+=("--------------------------------------------------------")
  box_arr+=("")

  local total_recommended_threads=$(($num_threads_by_speed + disp_threads_need + 1))
  msg="Total recommended threads is ${total_recommended_threads}."
  box_arr+=("${msg}")
  WriteLog "${msg}" "DEBUG"

  if [ $total_recommended_threads -gt $(($cores_length - 1)) ];then
    msg="[WARNING] Available cores num is ${cores_length}. It is not enough."
    box_arr+=("${msg}")
    WriteLog "${msg}" "DEBUG"
  fi

  box_arr+=("")
  msg="Total recommended cores to isolate is ${total_recommended_threads}."
  box_arr+=("${msg}")
  box_arr+=("")
  box_arr+=("--------------------------------------------------------")
  box_arr+=("")


  local cores_need=0
  if [ $(($num_threads_by_speed + $disp_threads_need + 1)) == $cores_length ];then
    cores_need=$(($num_threads_by_speed + $disp_threads_need))
    box_arr+=("[WARNING] We will isolate only ${cores_need} cores for DPI:")
    box_arr+=(" * ${num_threads_by_speed} for num_threads;")
    box_arr+=(" * ${disp_threads_need} for dispatcher;")
    box_arr+=(" * service will work at the same core as OS;")
  else
    cores_need=$(($num_threads_by_speed + $disp_threads_need + 1))
    if [ $cores_need -lt $cores_length ]; then
      box_arr+=("We will isolate only ${cores_need} cores for DPI:")
      box_arr+=(" * ${num_threads_by_speed} for num_threads;")
      box_arr+=(" * ${disp_threads_need} for dispatcher;")
      box_arr+=(" * 1 for service;")
    else
      msg="[ERROR] Not enough cores for current configuration(Available cores number is ${cores_length}, recommended cores number is ${cores_need})"
      box_arr+=("${msg}")
      WriteLog "${msg}" "ERROR"
    fi
  fi

  print_box "${box_arr[@]}"

  use_default_configuration=0

  if ! [ $cores_need -lt $cores_length ]; then
    if [ $mode == "interactive" ]; then
      local q="Do you want to use default CPU configuration (We will isolate only $(($cores_length - 1)) cores for DPI)?  [Y/n](Yes is default, No - exit) "

      def=$(YesNoHandler "$q" "y")
    else
      def="y"
    fi

    case $def in
      [Yy]*)
        use_default_configuration=1
        ;;
      [Nn]*)
        EngineerExit
        ;;
    esac
  else
    if [ $mode == "interactive" ]; then
      local q="Do you want to use this CPU configuration? [Y/n](Yes is default, No - We will isolate only $(($cores_length - 1)) cores for DPI) "

      rec=$(YesNoHandler "$q" "y")
    else
      rec="y"
    fi

    case $rec in
      [Yy]*)
        ;;
      [Nn]*)
        use_default_configuration=1
        ;;
    esac
  fi


  WriteLog "Use default CPU configuration answer is ${use_default_configuration}" "DEBUG"

  if [ $use_default_configuration == 0 ];then
    UpdateNumThreads $num_threads_need

    local config_cores_arr=("${cores_arr[@]:1:$cores_need}")
    SAVE_IFS="$IFS"
    IFS=","
    local user_threads="${config_cores_arr[*]}"
    cores="${cores_arr[*]}"
    IFS="$SAVE_IFS"
    print_box "Available cores list is $cores" "DPI will use CPU cores: $user_threads"
    WriteLog "Available cores list is $cores. DPI will use CPU cores: $user_threads" "DEBUG"

    if [ $mode == "interactive" ]; then
      local q="Do you want to use this config?  [Y/n](Yes is default, No is reconfig by input) "
      agree=$(YesNoHandler "$q" "y")
    else
      agree="y"
    fi

    WriteLog "Use cores default config answer is ${agree}" "DEBUG"
    case $agree in
    [Yy]*) ;;

    [Nn]*)
      user_threads=""
      PrintLightDelimeter
      print_info "Available cores list is $cores"
      re_is_number='^[0-9]+$'
      while read -p "Input CPU cores for DPI (separate cores by \",\"(comma)): " c; do
        if [ ! -z "$c" ]; then
          local str=${c//[[:blank:]]/}
          SAVE_IFS="$IFS"
          IFS=","
          read -r -a input_arr <<<"$str"
          IFS="$SAVE_IFS"
          is_error=0
          for el in "${input_arr[@]}"; do
            if ! [[ $el =~ $re_is_number ]]; then
              print_error "$el is not a number!"
              is_error=1
            else
              local found=0
              for i in "${cores_arr[@]}"; do
                if [ $i == $el ]; then
                  found=1
                fi
              done

              if [ $found -eq 0 ]; then
                print_error "Core $el does not available!"
                is_error=1
              fi
            fi
          done

          if [ "${#input_arr[@]}" -lt $cores_need ]; then
            msg="[ERROR] You input ${#input_arr[@]} cores (${str}), have to be ${cores_need} cores!"
            print_error "${msg}"
            WriteLog "${msg}" "ERROR"
            is_error=1
          fi

          if [ $is_error -eq 0 ]; then
            user_threads="${str}"
            break
          fi
        fi
      done

      WriteLog "Selected user threads is ${user_threads}" "DEBUG"
      print_info "Selected user threads is ${user_threads}"
      ;;
    esac
  else
    local config_cores_arr=("${cores_arr[@]:1}")
    SAVE_IFS="$IFS"
    IFS=","
    local user_threads="${config_cores_arr[*]}"
    cores="${cores_arr[*]}"
    IFS="$SAVE_IFS"
    print_box "Available cores list is $cores" "DPI will use CPU cores: $user_threads"
    WriteLog "Available cores list is $cores" "DPI will use CPU cores: $user_threads" "DEBUG"

    if [ $mode == "interactive" ]; then
      local q="Do you want to use this config?  [Y/n](Yes is default, No is reconfig by input) "
      agree=$(YesNoHandler "$q" "y")
    else
      agree="y"
    fi

    WriteLog "Use cores default config answer is ${agree}" "DEBUG"
    case $agree in
    [Yy]*) ;;

    [Nn]*)
      user_threads=""
      PrintLightDelimeter
      print_info "Available cores list is $cores"
      re_is_number='^[0-9]+$'
      while read -p "Input CPU cores for DPI (separate cores by \",\"(comma)): " c; do
        if [ ! -z "$c" ]; then
          local str=${c//[[:blank:]]/}
          SAVE_IFS="$IFS"
          IFS=","
          read -r -a input_arr <<<"$str"
          IFS="$SAVE_IFS"
          is_error=0
          for el in "${input_arr[@]}"; do
            if ! [[ $el =~ $re_is_number ]]; then
              print_error "$el is not a number!"
              is_error=1
            else
              local found=0
              for i in "${cores_arr[@]}"; do
                if [ $i == $el ]; then
                  found=1
                fi
              done

              if [ $found -eq 0 ]; then
                print_error "Core $el does not available!"
                is_error=1
              fi
            fi
          done

          if [ $is_error -eq 0 ]; then
            user_threads="${str}"
            break
          fi
        fi
      done

      WriteLog "Selected user threads is ${user_threads}" "DEBUG"
      print_info "Selected user threads is ${user_threads}"
      ;;
    esac
  fi

  new_grub="${grub} default_hugepagesz=${hugepagesz} hugepagesz=${hugepagesz} hugepages=${hugepages} spectre_v2=${spectre} nopti elevator=deadline isolcpus=${user_threads}"
  WriteLog "New grub config is ${new_grub}" "DEBUG"
  grub_line="\"${new_grub}\""

  rplc="GRUB_CMDLINE_LINUX=${grub_line}"

  sed -i "/GRUB_CMDLINE_LINUX/c${rplc}" $file

  grub2-mkconfig -o /boot/grub2/grub.cfg

  #Restart kernel
  if [ $hugepages -eq 8 ]; then
    echo 8 >/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
  else
    echo 512 >/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
  fi

  #Add DPI and PCRF to startup
  systemctl --now enable fastdpi
  systemctl --now enable fastpcrf
  WriteLog "EDIT CORE FINISH" "DEBUG"
  print_info "EDIT CORE FINISH"
}

cloud_api="aHR0cHM6Ly9jbG91ZC52YXNleHBlcnRzLnJ1L2FwaS9nZXRfZHBpX2xpYy8="

function DetectBondedDevices()
{
  WriteLog "DETECT BONDED INTERFACES START" "DEBUG"
  bonded_devices=()

  if [ $network_manager_installed == "0" ]; then
#    if [ $CentOsVersion -ge 8 ]; then
#      dnf install -y NetworkManager
#    else
#      yum install -y NetworkManager
#    fi
    print_error "NetworkManager not installed!"
    WriteLog "NetworkManager not installed!" "ERROR"
    return
  fi

  while read type device; do
    if [ ! -z $type ] && [ ! -z $device ]; then
      if [ $type == "bond" ] && [ $device != "--" ];then
        WriteLog "Detected bond device ${device}!" "DEBUG"
        while read interface; do
          bonded_devices[$interface]="${interface}"
          WriteLog "Detected bond interface ${interface}!" "DEBUG"
        done <<< $(cat /proc/net/bonding/$device | grep "Slave Interface:" | awk '{print $3}')
      fi
    fi
  done <<< $(nmcli connection show | grep bond | awk '{print $3 " " $4}')

  WriteLog "DETECT BONDED INTERFACES FINISH" "DEBUG"
}

function DetectInterfacesSpeeds()
{
  WriteLog "DETECT INTERFACES SPEEDS START" "DEBUG"
  interfaces_speeds=()
  local txt_file=$SCRIPT_DIR/interfaces.txt
  lshw -class network -quiet -sanitize -numeric -notime > "${txt_file}"
  current_interface=''
  while read line; do
    if [[ $line =~ "bus info: " ]]; then
      for interface in "${!interface_list[@]}"; do
        if [[ $line =~ $interface ]]; then
          current_interface="${interface}"
          break
        fi
      done
    fi

    if [ "$current_interface" == "" ]; then
      continue
    fi

    if [[ $line =~ "capacity: " ]]; then
      local speed="${line}"
      speed=${speed//"capacity: "/}
      if [[ $speed =~ "Gbit/s" ]]; then
        speed=${speed//"Gbit/s"/}
        speed=$(($speed * 1000))
      else
        speed=1000
      fi
      interfaces_speeds[$current_interface]=$speed
    fi
  done < $txt_file

  WriteLog "DETECT INTERFACES SPEEDS END" "DEBUG"
}

function SelectInterfaces() {
  print_info "SELECT INTERFACES START"
  WriteLog "SELECT INTERFACES START" "DEBUG"
  #Install net-tools
  InstallNetTools

  interface_list=()
  interface_names=()
  interface_ips=()

  interfaces=()
  in_dev=()
  in_dev_config=()
  out_dev=()
  out_dev_config=()
  bridges=()
  total_bridges_speed=0

  #Select Ethernet interface
  ssh_start=("${SSH_CLIENT%% *}")
  ssh=("$SSH_CONNECTION")
  ssh_ip=$(echo $ssh | grep $ssh_start | awk '{print $3}')

  DetectBondedDevices

  if [ $use_only_valid_interfaces == 0 ]; then
    for interface in $(lspci -D | grep Eth | awk '{print $1}'); do
      interface_list[$interface]=$interface
      name=$(ls -l /sys/class/net/ | grep ${interface} | awk '{print $9}')
      interface_names[$interface]=$name

      ip=$(ip -br a | grep $name | awk '{print $3}')
      interface_ips[$interface]=$ip

      WriteLog "Interface ${interface} ( name = ${name} | ip = ${ip} )" "DEBUG"
    done
  else
    while read interface_full; do
      if ! [[ -z $interface_full ]]; then
        local found=0
        for eth in "${available_interfaces[@]}"; do
          if [[ "${interface_full}" == *"$eth"* ]];then
            found=1
            break
          fi
        done
        if [ $found == 1 ];then
          interface=$(echo "${interface_full}" | awk '{print $1}')

          interface_list[$interface]=$interface
          name=$(ls -l /sys/class/net/ | grep ${interface} | awk '{print $9}')
          interface_names[$interface]=$name

          ip=$(ip -br a | grep $name | awk '{print $3}')
          interface_ips[$interface]=$ip

          WriteLog "Interface ${interface} ( name = ${name} | ip = ${ip} )" "DEBUG"
        fi
      fi
    done <<< $(lspci -D |grep Eth)
  fi


  declare -A interfaces_detected

  interface_num=0
  declare -A inteface_lst=()
  declare -A interface_nums=()

  declare -A interface_options=()

  local ssh_exists=0
  DetectInterfacesSpeeds

  for interface in "${!interface_list[@]}"; do
    interface_num=$(($interface_num + 1))
    inteface_lst[$interface_num]=$interface
    interface_nums[$interface_num]=$interface_num

    if [ ! -z "${interface_names[$interface]}" ];then
      local speed=0
      if [ -z "${interfaces_speeds[$interface]}" ]; then
        speed=1000
      else
        speed="${interfaces_speeds[$interface]}"
      fi
      interface_options["${interface}"]="${interface_names[$interface]}($interface ${speed}Mb/s) "
    else
      interface_options["${interface}"]="${interface_names[$interface]}($interface) "
    fi

    if [ ! -z "${interface_names[$interface]}" ] && [ ! -z "${bonded_devices[${interface_names[$interface]}]}" ]; then
      interface_options[$interface]="${interface_options[$interface]}(Bonded interface!!!)"
      interfaces_detected[$interface]="b"
    elif [ -z "${interface_ips[$interface]}" ]; then
      interface_options[$interface]="${interface_options[$interface]}(No active internet connection, likely in)"
      interfaces_detected[$interface]="i"
    else
      if [[ "${interface_ips[$interface]}" == *"$ssh_ip"* ]]; then
        interface_options[$interface]="${interface_options[$interface]}(SSH connected on interface, selecting will cause ssh disconnect)"
        interfaces_detected[$interface]="s"
        ssh_exists=1
      elif [ $(ifconfig ${interface_names[$interface]} | grep "inet" | wc -l) != '0' ]; then
        interface_options[$interface]="${interface_options[$interface]} (Active internet connection, likely out)"
        interfaces_detected[$interface]="o"
      else
        interface_options[$interface]="${interface_options[$interface]}(No active internet connection, likely in)"
        interfaces_detected[$interface]="i"
      fi
    fi
  done

  local box_arr=()
  box_arr+=("List of Ethernet interfaces:")
  box_arr+=(" ")
  interface_num=0
  for interface in "${interface_options[@]}"; do
    interface_num=$(($interface_num + 1))
    box_arr+=("${interface_num}. $interface")
  done
  print_box "${box_arr[@]}"
  #    PrintLightDelimeter

  local max_bridges=$((($interface_num - $ssh_exists) / 2))

  if [ "$mode" == "interactive" ]; then
    local q="Do you want to select in|out interfaces yourself? (No is default) [y|N] "
    yn=$(YesNoHandler "${q}" "n")
  else
    yn="n"
  fi

  WriteLog "Select in|out interfaces answer is ${yn}}" "DEBUG"
  case $yn in
  [Yy]*)
    PrintLightDelimeter
    while read -p "Do you want to add device pair? (Yes is default) [Y|n] " yy; do
      if [ -z "$yy" ]; then
        yy="y"
      fi
      WriteLog "Add device pair answer is ${yy}}" "DEBUG"
      case $yy in
      [Yy]*)
        local in_interface=""
        local out_interface=""
        local in_interface_index
        local out_interface_index

        box_arr=()
        interface_num=0
        for interface in "${interface_options[@]}"; do
          interface_num=$(($interface_num + 1))
          box_arr+=("${interface_num}. $interface")
        done

        print_box "${box_arr[@]}"
        in_speed=0
        out_speed=0
        while read -p "Select In interface (line number) [Empty to continue]: " i; do
          if [ ! -z "$i" ]; then
            if [ ! -z "${inteface_lst[$i]}" ]; then
              if [ -z "${in_dev[${inteface_lst[$i]}]}" ] && [ -z "${out_dev[${inteface_lst[$i]}]}" ]; then
                in_dev[${inteface_lst[$i]}]=$(ConvertDevNameForConfig ${inteface_lst[$i]})
                in_dev_config+=("${in_dev[${inteface_lst[$i]}]}")
                interface_options[${inteface_lst[$i]}]="(selected, in) ${interface_options[${inteface_lst[$i]}]}"
                in_interface="${in_dev[${inteface_lst[$i]}]}"
                in_interface_index="${inteface_lst[$i]}"

                WriteLog "Selected In interface is ${interface_options[${inteface_lst[$i]}]}" "DEBUG"

                if [ ! -z "${interfaces_speeds[${inteface_lst[$i]}]}" ];then
                  in_speed=${interfaces_speeds[${inteface_lst[$i]}]}
                  # CalculateTotalInterfacesSpeed "${interfaces_speeds[${inteface_lst[$i]}]}" "add"
                else
                  local msg="Speed for interface ${in_dev[${inteface_lst[$i]}]}(${inteface_lst[$i]}) not detected!"
                  WriteLog "${msg}" "ERROR"
                  print_error "${msg}"
                fi
                break
              fi
              box_arr=()
              interface_num=0
              for interface in "${interface_options[@]}"; do
                interface_num=$(($interface_num + 1))
                box_arr+=("${interface_num}. $interface")
              done
              print_box "${box_arr[@]}"

            fi
          else
            WriteLog "Select In interface break" "DEBUG"
            break
          fi
        done

        if [ -z "${in_interface_index}" ]; then
          break
        fi

        box_arr=()
        interface_num=0
        for interface in "${interface_options[@]}"; do
          interface_num=$(($interface_num + 1))
          box_arr+=("${interface_num}. $interface")
        done

        print_box "${box_arr[@]}"

        while read -p "Select Out interface (line number) [Empty to continue]: " i; do
          if [ ! -z "$i" ]; then
            if [ ! -z "${inteface_lst[$i]}" ]; then
              if [ -z "${in_dev[${inteface_lst[$i]}]}" ] && [ -z "${out_dev[${inteface_lst[$i]}]}" ]; then
                out_dev[${inteface_lst[$i]}]=$(ConvertDevNameForConfig ${inteface_lst[$i]})
                out_dev_config+=("${out_dev[${inteface_lst[$i]}]}")
                interface_options[${inteface_lst[$i]}]="(selected, out) ${interface_options[${inteface_lst[$i]}]}"
                out_interface="${out_dev[${inteface_lst[$i]}]}"
                out_interface_index="${inteface_lst[$i]}"
                WriteLog "Selected Out interface is ${interface_options[${inteface_lst[$i]}]}" "DEBUG"

                if [ ! -z "${interfaces_speeds[${inteface_lst[$i]}]}" ];then
                  out_speed="${interfaces_speeds[${inteface_lst[$i]}]}"
#                  CalculateTotalInterfacesSpeed "${interfaces_speeds[${inteface_lst[$i]}]}" "add"
                else
                  local msg="Speed for interface ${in_dev[${inteface_lst[$i]}]}(${inteface_lst[$i]}) not detected!"
                  WriteLog "${msg}" "ERROR"
                  print_error "${msg}"
                fi

                break
              fi
              box_arr=()
              interface_num=0
              for interface in "${interface_options[@]}"; do
                interface_num=$(($interface_num + 1))
                box_arr+=("${interface_num}. $interface")
              done
              print_box "${box_arr[@]}"
            fi
          else
            WriteLog "Select Out interface break" "DEBUG"
            break
          fi
        done

        if [ -z "${in_dev[$in_interface_index]}" ] || [ -z "${out_dev[$out_interface_index]}" ]; then
          if [ -z "${in_dev[$in_interface_index]}" ]; then
            unset -v "out_dev[$out_interface_index]"
          else
            unset -v "in_dev[$in_interface_index]"
          fi

          break
        fi

        local bridge="[${in_interface}] <====[DPI]====> [${out_interface}]"

        WriteLog "Bridge is ${bridge}" "DEBUG"
        PrintLightDelimeter
        local sp=0
        if [ $in_speed -lt $out_speed ];then
          sp=$in_speed
        else
          sp=$out_speed
        fi
        print_info "Bridge is $bridge"
        print_info "Bridge speed is ${sp}Mb/s"
        CalculateTotalInterfacesSpeed "${sp}" "add"
        bridges+=("${bridge}")

        unset -v "in_interface"
        unset -v "out_interface"
        unset -v "in_interface_index"
        unset -v "out_interface_index"
        unset -v "in_speed"
        unset -v "out_speed"

        ;;

      [Nn]*)
        break
        ;;
      esac

      if [[ "${#bridges[@]}" == "${max_bridges}" ]]; then
        break
      fi
    done
    ;;
  [Nn]*)
    local lst_dir="out"
    for i in "${!interfaces_detected[@]}"; do
      dev=$(ConvertDevNameForConfig $i)
      if [ "${interfaces_detected[$i]}" != "s" ] && [ "${interfaces_detected[$i]}" != "b" ]; then
        if [ $lst_dir == "out" ]; then
          in_dev[$i]=$dev
          in_dev_config+=("${dev}")
          lst_dir="in"
        else
          out_dev[$i]=$dev
          out_dev_config+=("${dev}")
          lst_dir="out"
        fi

      fi
    done

    while [ "${#in_dev[@]}" != "${#out_dev[@]}" ]; do
      last=""
      last_cfg=""
      if [ "${#in_dev[@]}" -gt "${#out_dev[@]}" ]; then
        for i in "${!in_dev[@]}"; do
          last=$i
        done
        out_dev[$last]=${in_dev[$last]}
        unset -v "in_dev[$last]"

        for i in "${!in_dev_config[@]}"; do
          last_cfg=$i
        done
        out_dev_config+=("${in_dev_config[$last_cfg]}")
        unset -v "in_dev_config[$last_cfg]"
      else
        for i in "${!out_dev[@]}"; do
          last=$i
        done
        in_dev[$last]=${out_dev[$last]}
        unset -v "out_dev[$last]"

        for i in "${!out_dev_config[@]}"; do
          last_cfg=$i
        done
        in_dev_config+=("${out_dev_config[$last_cfg]}")
        unset -v "out_dev_config[$last_cfg]"
      fi

      if [[ "${#in_dev[@]}" == "${max_bridges}" ]] || [[ "${#out_dev[@]}" == "${max_bridges}" ]]; then
        last=""
        last_cfg=""
        if [[ "${#in_dev[@]}" -gt "${max_bridges}" ]]; then
          for i in "${!in_dev[@]}"; do
            last=$i
          done

          unset -v "in_dev[$last]"

          for i in "${!in_dev_config[@]}"; do
            last_cfg=$i
          done
          unset -v "in_dev_config[$last_cfg]"

        elif [[ "${#out_dev[@]}" -gt "${max_bridges}" ]]; then
          for i in "${!out_dev[@]}"; do
            last=$i
          done

          unset -v "out_dev[$last]"

          for i in "${!out_dev_config[@]}"; do
            last_cfg=$i
          done
          unset -v "out_dev_config[$last_cfg]"
        fi
        break
      fi
    done

    bridge_num=0
    declare -A in_speeds=()
    for i in "${!in_dev[@]}"; do
      local bridge="[${in_dev[$i]}] <====[DPI]====> "
      bridges[$bridge_num]="${bridge}"
      if [ ! -z "${interfaces_speeds[$i]}" ];then
        in_speeds[$bridge_num]="${interfaces_speeds[$i]}"
      else
        in_speeds[$bridge_num]=0
      fi
      bridge_num=$(($bridge_num + 1))
    done

    bridge_num=0
    for i in "${!out_dev[@]}"; do
      if [ -z "${bridges[$bridge_num]}" ]; then
        bridges[$bridge_num]=" <====[DPI]====> "
      fi

      bridges[$bridge_num]="${bridges[$bridge_num]}[${out_dev[$i]}]"

      local sp=0
      if [ ! -z "${interfaces_speeds[$i]}" ];then
        if [ "${in_speeds[$bridge_num]}" == 0 ]; then
          sp="${interfaces_speeds[$i]}"
        elif [ "${interfaces_speeds[$i]}" -lt "${interfaces_speeds[$i]}" ]; then
          sp="${interfaces_speeds[$i]}"
        else
          sp="${in_speeds[$bridge_num]}"
        fi
      else
        sp="${in_speeds[$bridge_num]}"
      fi

      if [ $sp == 0 ];then
        local msg="Speed for bridge ${bridges[$bridge_num]} is unknown!"
        WriteLog "${msg}" "ERROR"
        print_error "${msg}"
      fi

      CalculateTotalInterfacesSpeed "${sp}" "add"

      bridge_num=$(($bridge_num + 1))
    done

    ;;
  esac

  if [[ "${#bridges[@]}" -eq 0 ]]; then
    print_error "[ERROR] No bridges detected!"
    SelectInterfaces
    return
  fi

  if [[ "${#in_dev[@]}" -eq 0 ]]; then
    print_error "[ERROR] No In interfaces detected!"
    SelectInterfaces
    return
  fi

  if [[ "${#out_dev[@]}" -eq 0 ]]; then
    print_error "[ERROR] No In interfaces detected!"
    SelectInterfaces
    return
  fi

  if [ $total_bridges_speed -le 0 ];then
    print_error "[ERROR] Total selected bridges speed is unknown (${total_bridges_speed})!"
#    SelectInterfaces
#    return
  fi

  box_arr=()

  SAVE_IFS="$IFS"
  IFS=","
  local in_str="${in_dev[*]}"
  msg="Selected In interfaces: ${in_str}"
  WriteLog "$msg" "DEBUG"
  box_arr+=("${msg}")

  local out_str="${out_dev[*]}"
  msg="Selected Out interfaces: ${out_str}"
  WriteLog "$msg" "DEBUG"
  box_arr+=("${msg}")

  IFS="$SAVE_IFS"
  msg=$'Selected bridges:'
  box_arr+=("${msg}")
  for bridge in "${bridges[@]}"; do
    msg=$msg$'\n'$bridge
    box_arr+=(" ${bridge}")

    WriteLog "Bridge is ${bridge}" "DEBUG"
  done

  WriteLog "$msg" "DEBUG"

  if [ "$mode" == "interactive" ]; then
    local box_msg=()
    box_msg+=("Total selected bridges speed is ${total_bridges_speed}Gb/s!")
    local message="Do you want to change total bridges speed? (y - Input total bridges speed; N - continue install(default)) "
    box_msg+=("${message}")
    print_box "${box_msg[@]}"
    yn=$(YesNoHandler "${message}" "n")
  else
    yn="n"
  fi

  case $yn in
  [Yy]*)
    read -p "Enter the total bridges speed value in Gb/s (value should be integer): " spd
    re='^[0-9]+$'
    while ! [[ $spd =~ $re ]] || [[ $spd -eq 0 ]]; do
      if [ -z $spd ]; then
        break
      fi
      PrintLightDelimeter
      read -p "Incorrect value! Enter the total bridges speed value in Gb/s (value should be integer): " spd
    done

    if ! [ -z $spd ]; then
      total_bridges_speed="${spd}"
    fi
    ;;
  esac

  msg="Total selected bridges speed is ${total_bridges_speed}Gb/s!"
  box_arr+=("")
  box_arr+=("${msg}")

  WriteLog "$msg" "DEBUG"

  print_box "${box_arr[@]}"
  WriteLog "SELECT INTERFACES FINISH" "DEBUG"
  print_info "SELECT INTERFACES FINISH"

  if [ "$mode" == "interactive" ]; then
    local q="Do you want to continue install? (Y - continue install(default); n - detect and select interfaces) "
    yn=$(YesNoHandler "${q}" "y")
  else
    yn="y"
  fi

  case $yn in
  [Nn]*)
    SelectInterfaces
    return
    ;;
  esac
}

function CreateService() {
  touch $service
  echo '[Unit]' >>$service
  echo 'Description=Continues fastinstall.sh script after reboot' >>$service
  echo '' >>$service
  echo 'Type=simple' >>$service
  echo "ExecStart=$SCRIPT_DIR/fastinstall.sh" >>$service
  echo 'TimeoutStartSec=0' >>$service
  echo '' >>$service
  echo '[Install]' >>$service
  echo 'WantedBy=default.target' >>$service
}

function RemoveService() {
  systemctl stop $service_name
  systemctl disable $service_name
  rm -f $service
  rm -f "/usr/lib/systemd/system/$service_name.service" # and symlinks that might be related
  rm -f "/usr/lib/systemd/system/$service_name.service"
  rm -f "/usr/lib/systemd/system/$service_name.service" # and symlinks that might be related
  systemctl daemon-reload
  systemctl reset-failed
}

function RebootOS() {
  if [ "$mode" == "interactive" ]; then
    local q="Do you want to reboot system? [Y/n](Yes is default) "
    ask=$(YesNoHandler "${q}" "y")
  else
    ask="y"
  fi
  case $ask in
  [Yy]*) reboot ;;
  [Nn]*) ;;
  esac
}

function UpdateYumReposUrls()
{
  WriteLog "Update Yum repositories urls" "DEBUG"
  if [ $IsCentosStream == 0 ] && [ $IsVEOS == 0 ];then
    sed -i -e '/^mirrorlist=http:\/\//d' -e 's/^# *baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/' /etc/yum.repos.d/CentOS-*.repo
  fi
  WriteLog "Update Yum repositories urls" "DEBUG"
}

#MAIN FUNCTIONS
#Checks operating system and hardware for compatibility with dpi
function CheckSystem() {

  print_info "CHECK SYSTEM START"

  WriteLog "CHECK SYSTEM START" "DEBUG"

  local need_to_exit=0
  # Check OS version
  CENTOSRELEASE=$(cat /etc/system-release)
  CentOsVersion=6

  TestVersion "CentOS Linux release"
  TestVersion "CentOS Stream release"
  TestVersion "Oracle Linux Server release"
  TestVersion "Red Hat Enterprise Linux release"
  TestVersion "VEOS release"

  WriteLog "CHECK SYSTEM OsVersion=${CentOsVersion}" "DEBUG"
  if [ $CentOsVersion -lt $min_os_version ]; then
    print_error_box "Operating System is out of date, your OS version is $CENTOSRELEASE, pl"
    if [ "$mode" == "interactive" ]; then
      local q="Do you want to update OS? [Y/n](Yes is default) "
      yn=$(YesNoHandler "${q}" "y")
    else
      yn="y"
    fi
    case $yn in
    [Yy]*)
      if [ $CentOsVersion -ge 8 ]; then
        dnf update -y
      else
        yum update -y
      fi
      RebootOS
      ;;
    [Nn]*) EngineerExit ;;
    esac
  fi

  UpdateYumReposUrls
  yum install -y pciutils

  local errors=()
  # Check free disk space
  free_space=$(df -PBG "$PWD" | awk 'NR==2{print $4}' | sed -e "s/G$//")

  WriteLog "CHECK SYSTEM free_space=${free_space}" "DEBUG"
  if [ $free_space -lt $min_disk_space ]; then
    msg="Not enough disk space, you have $free_space GB free, you need at least $min_disk_space GB free to continue installation."
    WriteLog "$msg" "Error"

    errors+=("${msg}")
    errors+=("Please free up some space and launch script again")
    errors+=("")
    need_to_exit=1
  fi

  # Check number of CPU cores
  if [ $dpi_installed == "0" ]; then
    WriteLog "CHECK SYSTEM threads=${threads}" "DEBUG"
    if [ $threads -lt $min_num_cores ]; then
      msg="Not enough CPU cores, you have $threads cores, you need at least $min_num_cores cores to continue installation."
      WriteLog "$msg" "Error"

      errors+=("${msg}")
      errors+=("If you are using a Virtual Machine increase the number of cores in VM settings and launch script again,")
      errors+=("if using a physical machine try running the script again on a faster computer")
      errors+=("")
      need_to_exit=1
    fi
  fi

  #Check amount of RAM
  installed_ram=$(free -g | awk 'NR==2{print $2}')
  WriteLog "CHECK SYSTEM installed_ram=${installed_ram}" "DEBUG"
  if [ $installed_ram -lt $min_ram ]; then
    msg="Not enough installed RAM, you have $installed_ram GB of installed RAM, you need at least $min_ram GB to continue installation"
    WriteLog $msg "Error"

    errors+=("${msg}")
    errors+=("If you are using a Virtual Machine increase the amount of RAM,")
    errors+=("if using a physical machine install more RAM or try a faster computer")
    errors+=("")

    need_to_exit=1
  fi

  #Check sse4_2
  sse4_available=$(grep -o sse4_2 /proc/cpuinfo | wc -l)
  if [ $sse4_available -lt 1 ]; then
    msg="sse4_2 is not available. Result of sse4_2 check is ${sse4_available}."
    WriteLog $msg "Error"
    errors+=("${msg}")
    errors+=("")

    need_to_exit=1
  fi

  #Check hyper threading
  if [ $disable_hyper_threading_check == 0 ]; then
    threads_per_core=$(lscpu | grep "Thread(s) per core" | awk '{print $4}')
    if [ $threads_per_core -gt 1 ]; then
      msg="Hyper threading is enabled."
      WriteLog $msg "Error"
      errors+=("${msg}")
      errors+=("Disable Hyper threading using BIOS.")
      errors+=("")

      need_to_exit=1
    fi
  fi

  #Check NUMA node(s)
  numa_nodes=$(lscpu | grep "NUMA node(s)" | awk '{print $3}')
  if [ $numa_nodes -gt 1 ]; then
    msg="Detected more than 1 NUMA nodes."
    WriteLog $msg "Error"
    errors+=("${msg}")
    errors+=("Please disable other NUMA node(s).")
    errors+=("")

    need_to_exit=1
  fi

  #Check interfaces and NUMA node(s)
  for interface in $(lspci -D | grep Eth | awk '{print $1}'); do
    name=$(ls -l /sys/class/net/ | grep ${interface} | awk '{print $9}')
    if [ ! -z "${name}" ]; then
      node_num=$(cat /sys/class/net/$name/device/numa_node)

      if [ $node_num -gt 0 ]; then
        msg="Interface ${name} (${interface}) working on NUMA node${node_num}."
        WriteLog $msg "Error"
        errors+=("${msg}")
        errors+=("Should be node0.")
        errors+=("")

        need_to_exit=1
      fi
    fi
  done

  local encoding=$(locale charmap)
  if ! [[ $(echo $encoding | awk '{print tolower($0)}') =~ "utf-8" ]]; then
    msg="Your system is using ${encoding} encoding. Should be UTF-8!"
    WriteLog $msg "Error"
    errors+=("${msg}")
    errors+=("")

    need_to_exit=1
  fi

  local lang=$(echo $LANG | awk '{print tolower($0)}')
  if [[ $lang != *"ru_"* ]] && [[ $lang != *"en_"* ]]; then
    msg="Your system is using $LANG locale. Should be ru_RU or en_*!"
    WriteLog $msg "Error"
    errors+=("${msg}")
    errors+=("")
    need_to_exit=1
  fi

  if [ $disable_interfaces_check == 0 ];then
    local interfaces_count=0
    local valid_interfaces=()
    local wrong_interfaces=()
    while read interface; do
      if ! [[ -z $interface ]]; then
        interfaces_count=$(($interfaces_count + 1))
        local found=0
        for eth in "${available_interfaces[@]}"; do
          if [[ "${interface}" == *"$eth"* ]];then
            found=1
            break
          fi
        done
        if [ $found == 0 ];then
          wrong_interfaces+=("${interface}")
        else
          valid_interfaces+=("${interface}")
        fi
      fi
    done <<< $(lspci -D |grep Eth)

    local box_msg=()

    local has_errors=0
    if [ "${#valid_interfaces[@]}" -lt 2 ];then
      msg="Detected ${#valid_interfaces[@]} valid interfaces! Minimum valid interfaces is 2!"
      WriteLog $msg "Error"

      errors+=("${msg}")
      errors+=("")
      has_errors=1
      need_to_exit=1
    fi

    if [ "${#valid_interfaces[@]}" -gt 0 ];then
      box_msg+=("Valid interfaces list:")
      for eth in "${valid_interfaces[@]}"; do
        box_msg+=(" * ${eth} ;")
      done
    fi

    if [ "${#wrong_interfaces[@]}" -gt 0 ];then
      has_errors=1
      errors+=("Not valid interfaces list:")
      for eth in "${wrong_interfaces[@]}"; do
        errors+=(" * ${eth} ;")
      done
      errors+=("")
    fi

    if [ "${#errors[@]}" -gt 0 ];then
      print_error_box "${errors[@]}"
    fi

    if [ "${#errors[@]}" -gt 0 ] && [ $need_to_exit -eq 1 ];then
      EngineerExit
    fi
    
    print_box "${box_msg[@]}"

    if [ $has_errors == 1 ]; then
      local q1="Do you want to continue? [y/N](No is default) "
      local continue=$(YesNoHandler "${q1}" "n")
      case $continue in
        [Yy]*)
          local q2="Do you want to use only valid interfaces? [Y/n](Yes is default) "
          local use_v=$(YesNoHandler "${q2}" "y")
          case $use_v in
            [Yy]*) use_only_valid_interfaces=1;;
            [Nn]*) use_only_valid_interfaces=0;;
          esac
        ;;
        [Nn]*)
          EngineerExit
        ;;
      esac
    fi
  else
    if [ "${#errors[@]}" -gt 0 ];then
      print_error_box "${errors[@]}"
      EngineerExit
    fi
  fi

  WriteLog "CHECK SYSTEM FINISH" "DEBUG"
  print_info "CHECK SYSTEM FINISH"
}

function SetInterfaceOverride() {
  interface=$1
  driverctl -v set-override $interface vfio-pci
}

function UnsetInterfaceOverride() {
  interface=$1
  driverctl unset-override $interface
}

function ConfigDPDKDriver() {

  print_info "CONFIG DPDK DRIVER START"
  WriteLog "CONFIG DPDK DRIVER START" "DEBUG"

  echo "options vfio enable_unsafe_noiommu_mode=1" >/etc/modprobe.d/vfio-noiommu.conf

  for i in "${!in_dev[@]}"; do
    SetInterfaceOverride $i
  done

  for i in "${!out_dev[@]}"; do
    SetInterfaceOverride $i
  done

  driverctl list-overrides
  cat /sys/devices/virtual/dmi/id/product_uuid
  WriteLog "CONFIG DPDK DRIVER FINISH" "DEBUG"
  print_info "CONFIG DPDK DRIVER FINISH"
}

function RevertInterfaceDefaultDrivers() {
  for interface in $(lspci -D | grep Eth | awk '{print $1}'); do
    UnsetInterfaceOverride $interface
  done
}

function ArrayJoin() {
  (($#)) || return 1 # At least delimiter required
  local -- delim="$1" str IFS=
  shift
  str="${*/#/$delim}"     # Expand arguments with prefixed delimiter (Empty IFS)
  echo "${str:${#delim}}" # Echo without first delimiter
}

function ConfigDPI() {
  print_info "CONFIG DPI START"
  WriteLog "CONFIG DPI START" "DEBUG"

  #  SAVE_IFS="$IFS"
  #  IFS=":"
  #  local out_str="${out_dev_config[*]}"
  #  local in_str="${in_dev_config[*]}"
  #  IFS="$SAVE_IFS"

  local out_str=$(ArrayJoin ":" "${out_dev_config[@]}")
  local in_str=$(ArrayJoin ":" "${in_dev_config[@]}")

  EditConfig "in_dev" "$in_str"
  EditConfig "out_dev" "$out_str"

  enable_bl="y"
  if [ "$mode" == "interactive" ]; then
    local qa="Do you want to enable black list? [Y/n](Yes is default) "
    enable_bl=$(YesNoHandler "${qa}" "y")
  fi
  case $enable_bl in
  [Yy]*)
    EditConfig "federal_black_list" 1
    EditConfig "black_list_redirect" "http://vasexperts.ru/test/blocked.php"
    ;;
  [Nn]*)
    EditConfig "federal_black_list" 0
    EditConfig "black_list_redirect" ""
    ;;
  esac

  UpdateDpdkEngine

  WriteLog "Trying to detect DPI scale_factor" "DEBUG"
  if [ ${total_bridges_speed} != 0 ] && [ ! -z ${total_bridges_speed} ];then
    local scale_factor="${total_bridges_speed}"
    if [ $scale_factor -gt 10 ]; then
      scale_factor=10
    fi
    WriteLog "DPI scale_factor is ${scale_factor}" "DEBUG"
    EditConfig "scale_factor" $scale_factor

    WriteLog "DPI scale_factor installed" "DEBUG"
  else
    WriteLog "DPI scale_factor was not installed (bridges speed is ${total_bridges_speed} )" "ERROR"
  fi

  if [ "$mode" == "interactive" ]; then
    local q="Do you want to enable IPv6 for DPI?  [Y/n](Yes is default) "
    yn=$(YesNoHandler "${q}" "y")
  else
    yn="y"
  fi

  case $yn in
  [Yy]*)
    EditConfig "ipv6" 1
    ;;
  esac

  if [ "$CentOsVersion" -ge 8 ]; then
    systemctl restart fastdpi.service
  else
    service fastdpi restart
  fi
  WriteLog "CONFIG DPI FINISH" "DEBUG"
  print_info "CONFIG DPI FINISH"
}

function UpdateDpdkEngine() {
  print_info "CONFIG DPI dpdk_engine START"
  WriteLog "CONFIG DPI dpdk_engine START" "DEBUG"
  if [ "$mode" == "interactive" ]; then
    local q="Do you want to change dpdk_engine for DPI?  [y/N](No is default) "
    yn=$(YesNoHandler "${q}" "n")
  else
    yn="n"
  fi

  WriteLog "Change dpdk_engine for DPI answer is ${yn}}" "DEBUG"
  case $yn in
  [Yy]*)
    local box_arr=()
    box_arr+=("Possible values for dpdk_engine:")
    box_arr+=("")
    box_arr+=("    0. dpdk_engine=0 (default) - read/write default engine, one dispatcher for all;")
    box_arr+=("")
    box_arr+=("    1. dpdk_engine=1 - read/write engine with two dispatcher threads: for each direction by dispatcher;")
    box_arr+=("")
    box_arr+=("    2. dpdk_engine=2 - read/write engine with RSS support: for each direction dpdk_rss dispatchers are created (dpdk_rss=2 by default).")
    box_arr+=("       Thus, the total number of dispatchers = 2 * dpdk_rss;")
    box_arr+=("")
    box_arr+=("    3. dpdk_engine=3 - read/write engine with a separate dispatcher for each bridge.")
    box_arr+=("")
    box_arr+=("    4. dpdk_engine=4 - read/write engine with a separate dispatcher for each device.")

    print_box "${box_arr[@]}"

    declare -A dpdk_engine_options=([0]=0 [1]=1 [2]=2 [3]=3 [4]=4)

    read -p "Enter the dpdk_engine value [0(default), 1, 2, 3, 4]: " dpdk

    if [ -z "$dpdk" ]; then
      dpdk=${dpdk_engine_options[0]}
    fi

    while [ ! -n "${dpdk_engine_options[$dpdk]}" ]; do
      PrintLightDelimeter
      read -p "Incorrect value! Please enter the dpdk_engine value [0(default), 1, 2, 3, 4]: " dpdk
      if [ -z "$dpdk" ]; then
        dpdk=${dpdk_engine_options[0]}
      fi
    done

    WriteLog "Selected dpdk_engine value is ${dpdk}" "DEBUG"
    EditConfig "dpdk_engine" $dpdk
    ;;
  esac
  WriteLog "CONFIG DPI dpdk_engine FINISH" "DEBUG"
  print_info "CONFIG DPI dpdk_engine FINISH"
}

function UpdateNumThreads() {
  print_info "CONFIG DPI num_threads START"
  WriteLog "CONFIG DPI num_threads START" "DEBUG"
  local recommended_value="${1}"
  if [ "$mode" == "interactive" ]; then
    local q="Do you want to change num_threads for DPI? [y/N](No is default) "
    yn=$(YesNoHandler "${q}" "n")
  else
    yn="n"
  fi

  WriteLog "Change num_threads for DPI is ${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    local box_arr=()
    box_arr+=("CPU cores are perhaps the most critical resource for the Stingray SG.")
    box_arr+=("The more physical cores there are in the system, the more traffic can be processed by the SSG.")
    box_arr+=("")
    box_arr+=("[INFO] Stingray SG does not use Hyper-Threading: only real physical cores are taken into account, not logical ones.")
    box_arr+=("")
    box_arr+=("    * processing threads - process incoming packets and write to the TX-queue of the card;")
    box_arr+=("    * dispatcher threads - read the card's RX queues and distribute incoming packets among processing threads;")
    box_arr+=("    * service threads - perform deferred (time-consuming) actions, receive and process fdpi_ctrl and CLI, connection with PCRF, sending netflow;")
    box_arr+=("    * system kernel - dedicated to the operating system.")
    box_arr+=("")
    box_arr+=("Processing and dispatcher threads cannot be located on the same core. At start, Stingray SG binds threads to cores.")
    box_arr+=("Stingray SG by default selects the number of handler threads depending on the interface speed:")
    box_arr+=("    * 10G - 4 threads")
    box_arr+=("    * 25G - 8 threads")
    box_arr+=("    * 40G, 50G, 56G - 16 threads")
    box_arr+=("    * 100G - 32 threads")
    box_arr+=("")
    box_arr+=("For a group, the number of threads is equal to the sum of threads number for each pair")
    box_arr+=("")
    box_arr+=("In fastdpi.conf, you can specify the number of threads per bridge using the num_threads parameter.")
    box_arr+=("")
    box_arr+=("--------------------------------------------------------")
    box_arr+=("")
    box_arr+=("Recommended num_threads value is ${recommended_value}")

    print_box "${box_arr[@]}"

    read -p "Enter the num_threads value: " dpi_threads
    re='^[0-9]+$'
    while ! [[ $dpi_threads =~ $re ]] || [[ $dpi_threads -eq 0 ]]; do
      if [ -z $dpi_threads ]; then
        break
      fi
      PrintLightDelimeter
      read -p "Incorrect value! Please enter the num_threads value: " dpi_threads
    done

    if [ ! -z $dpi_threads ]; then
      WriteLog "Selected DPI num_threads value is ${dpi_threads}" "DEBUG"
      EditConfig "num_threads" $dpi_threads
    fi

    ;;
  esac
  WriteLog "CONFIG DPI num_threads FINISH" "DEBUG"
  print_info "CONFIG DPI num_threads FINISH"
}

function GetMemInfo() {
  local MemInfo=$(grep MemTotal /proc/meminfo)

  echo $MemInfo
}

function GetCPUInfo() {
  local info=$(lscpu)

  echo $info
}

function GetProductUUID() {
  info=$(cat /sys/devices/virtual/dmi/id/product_uuid)

  echo $info
}

function GetEthInfo() {
  info=$(lspci -D | grep Eth)

  echo $info
}

function UpdateOS() {

  print_info "UPDATE OS START"

  WriteLog "UPDATE OS START" "DEBUG"
  if [ "$mode" == "interactive" ]; then
    local q="Do you want to update OS? [Y/n] (Yes is default) "
    yn=$(YesNoHandler "${q}" "y")
  else
    yn="y"
  fi

  WriteLog "UPDATE OS answer=${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    if [ $CentOsVersion -ge 8 ]; then
      dnf update -y
    else
      yum update -y
    fi
    ;;
  [Nn]*) ;;
  esac

  WriteLog "UPDATE OS FINISH" "DEBUG"
  print_info "UPDATE OS FINISH"
}

function EnableRepos() {
  print_info "ENABLE REPOS START"
  WriteLog "ENABLE REPOS START" "DEBUG"
  rpm --import http://vasexperts.ru/centos/RPM-GPG-KEY-vasexperts.ru
  rpm -Uvh http://vasexperts.ru/centos/vasexperts-repo.noarch.rpm
  WriteLog "ENABLE REPOS FINISH" "DEBUG"
  print_info "ENABLE REPOS FINISH"
}

function InstallPackages() {
  print_info "INSTALL DPI PACKAGES START"
  WriteLog "INSTALL DPI PACKAGES START" "DEBUG"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf install -y fastdpi net-tools tar pciutils sysstat rsyslog logrotate driverctl || exit
  else
    yum install -y fastdpi net-tools tar pciutils sysstat rsyslog logrotate driverctl || exit
  fi
  WriteLog "INSTALL DPI PACKAGES FINISH" "DEBUG"
  print_info "INSTALL DPI PACKAGES FINISH"
}

function RemovePackages()
{
  print_info "REMOVE DPI PACKAGES START"
  WriteLog "REMOVE DPI PACKAGES START" "DEBUG"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf remove -y fastdpi
  else
    yum remove -y fastdpi
  fi
  WriteLog "REMOVE DPI PACKAGES FINISH" "DEBUG"
  print_info "REMOVE DPI PACKAGES FINISH"
}

function UpdatePackages() {

  print_info "UPDATE PACKAGES START"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf update -y fastdpi net-tools tar pciutils sysstat rsyslog logrotate driverctl
  else
    yum update -y fastdpi net-tools tar pciutils sysstat rsyslog logrotate driverctl
  fi
  print_info "UPDATE PACKAGES FINISH"
}

function InstallWget() {
  print_info "INSTALL WGET START"
  WriteLog "INSTALL WGET START" "DEBUG"

  if [ "$CentOsVersion" -ge 8 ]; then
    dnf install -y wget
  else
    yum install -y wget
  fi

  WriteLog "INSTALL WGET FINISH" "DEBUG"
  print_info "INSTALL WGET FINISH"
}

function InstallDpiui2() {
  print_info "INSTALL DPIUI2 START"

  WriteLog "INSTALL DPIUI2 START" "DEBUG"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf install -y --disableexcludes=all kernel-headers
  else
    yum install -y --disableexcludes=all kernel-headers
  fi

  local file=$SCRIPT_DIR/dpiui2-rpm_install.sh
  wget -O $file https://vasexperts.ru/install/dpiui2-rpm_install.sh
  sh $file
  WriteLog "INSTALL DPIUI2 FINISH" "DEBUG"
  print_info "INSTALL DPIUI2 FINISH"
}

function RemoveDpiui2()
{
  print_info "REMOVE DPIUI2 START"

  WriteLog "REMOVE DPIUI2 START" "DEBUG"

  if [ "$CentOsVersion" -ge 8 ]; then
    dnf remove -y dpiui2
  else
    yum remove -y dpiui2
  fi

  WriteLog "REMOVE DPIUI2 FINISH" "DEBUG"
  print_info "REMOVE DPIUI2 FINISH"
}

function InstallQoEStor() {

  print_info "INSTALL QoE Stor START"

  WriteLog "INSTALL QoE Stor START" "DEBUG"
  local file=$SCRIPT_DIR/fastor-rpm_install.sh
  wget -O $file https://vasexperts.ru/install/fastor-rpm_install.sh
  sh $file
  WriteLog "INSTALL QoE Stor FINISH" "DEBUG"
  print_info "INSTALL QoE Stor FINISH"
}

function RemoveQoEStor()
{
  print_info "REMOVE QoE Stor START"

  WriteLog "REMOVE QoE Stor START" "DEBUG"

  if [ "$CentOsVersion" -ge 8 ]; then
    dnf remove -y fastor
  else
    yum remove -y fastor
  fi

  WriteLog "REMOVE QoE Stor FINISH" "DEBUG"
  print_info "REMOVE QoE Stor FINISH"
}

function EnableChronyd() {
  print_info "ENABLE CHRONYD START"
  WriteLog "ENABLE CHRONYD START" "DEBUG"
  if [ "$CentOsVersion" -ge 7 ]; then
    systemctl --now enable chronyd
  else
    service chronyd enable
    service chronyd restart
  fi
  WriteLog "ENABLE CHRONYD FINISH" "DEBUG"
  print_info "ENABLE CHRONYD FINISH"
}

function PrintLightDelimeter() {
  echo "--------------------------------------------------------"
}

function PrintBoldDelimeter() {
  echo "========================================================"
}

function PrintLogo() {
  cat <<"EOF"


                             :
                           .--.
                          :----
                       .:------
   -                 :---------.
  .--            .:------------.
   ---  ...:::-----------------:               :::.     ..    +@*                                                     :::.      .:::.
   ----..----------------------:             +%#**%%= .+@*..  .-.  .  ..      ..  ..  .. ..   ...  .  ..    ..      +%#**%%=  :#@#**%%*.
.-:.----: :--------------------:             %@-:..:: %%@%%%* =@+ +@###%@+  =%%#%#@@ :@%#%* -%@%#%%@- %@:  +@+      %@=:. :: :@%:    -=-
  :..-----..-------------------:             :+*%%@#=  =@+    =@+ +@+  .@@ -@#   -@@ :@%:   @@:  .%@- .%%:=@*       :+*%%@#= +@+  *%%%%%
    ..:----:..-----------------:            .**   :@@  =@*    =@+ +@=  .@@ -@%:  +@@ :@%    %@:  :%@-  .%%@#       .**   :@@ :%%-   .*@@
       .:----:..---------------.             -#@%%%#-  .*@%%# =@+ +@=  .@@  -#@@%+@@ :@%    :*@%%#%@-   +@%         -#@%%%#-   =%@%%%=%@
          .:----:::------------.                                            ++:  =@#                   :%%.
             ..:--::::---------.                                            :*%%%#+                   .##.
                   ..:..::-----
                            ..:-.
                                 .:..
                                     ...


EOF

}

function AskInteractive() {
  local header=$(print_spaces 17 "------------------ Interactive mode ------------------")
  print_box "$header" " " "Enable interactive mode? (Yes is default) [Y|n]" "In interactive mode you can manage the installation process and edit the configuration." "If your answer is No, the installation will be done with the default settings."

  local q="Enable interactive mode? (Yes is default) [Y|n] "
  interactive=$(YesNoHandler "${q}" "y")

  case $interactive in
  [Yy]*) mode="interactive" ;;
  [Nn]*) mode="auto" ;;
  esac

  WriteLog "Set up mode=${mode}" "DEBUG"
  PrintBoldDelimeter
}

function GetTestLic() {

  WriteLog "Get test DPI lic START" "DEBUG"
  local filename_lic="/etc/dpi/fastdpi.lic"
  local filename_sig="/etc/dpi/fastdpi.sig"
  local n=0
  until [ $n -ge 15 ]; do
    if [ -f "${filename_lic}" ]; then
      break
    else
      n=$(($n + 1))
      print_info "Waiting for creation of ${filename_lic}"
      WriteLog "Waiting for creation of ${filename_lic}" "DEBUG"
      sleep 10
    fi
  done

  if [ $n -ge 15 ]; then
    print_error "${filename_lic} does not exists!"
    WriteLog "${filename_lic} does not exists!" "ERROR"
    return
  fi

  local uri=$(echo $cloud_api | base64 --decode)

  req_lic=$(curl -o $lic_local_file -X POST -k -O -F "lic_file=@${filename_lic}" $uri$cloud_code"/lic/"$lic_token --silent --write-out "%{http_code}\n")

  if [ $req_lic -eq 200 ]; then
    if [ -f $lic_local_file ] && [ $(cat $lic_local_file | wc -l) != 0 ]; then
      print_ok "DPI License file successfully downloaded!"
      WriteLog "DPI License file successfully downloaded!" "DEBUG"
      cat $lic_local_file
    else
      print_error "Failed to download DPI License file! [ ${lic_local_file} is empty ]"
      WriteLog "Failed to download DPI License file! [ ${lic_local_file} is empty ]" "ERROR"
      return
    fi
  else
    local err_msg=$(cat $lic_local_file)
    print_error "Failed to download DPI License file!" "[ CODE: ${req_lic} ] ${err_msg}"
    WriteLog "Failed to download DPI License file! [ CODE: ${req_lic} ] ${err_msg}" "ERROR"
    return
  fi

  req_sig=$(curl -o $sig_local_file -X POST -k -O -F "lic_file=@${filename_lic}" $uri$cloud_code"/sig/"$lic_token --silent --write-out "%{http_code}\n")

  if [ $req_sig -eq 200 ]; then
    if [ -f $sig_local_file ] && [ -s $sig_local_file ]; then
      print_ok "DPI License sig successfully downloaded!"
      WriteLog "DPI License sig successfully downloaded!" "DEBUG"
    else
      print_error "Failed to download license sig file! [ ${sig_local_file} is empty ]"
      WriteLog "Failed to download license sig file! [ ${sig_local_file} is empty ]" "ERROR"
    fi
  else
    local err_msg=$(cat $sig_local_file)
    print_error "Failed to download license sig file!" "[ CODE: ${req_sig} ] ${err_msg}"
    WriteLog "Failed to download license sig file! [ CODE: ${req_sig} ] ${err_msg}" "ERROR"
  fi

  if [ -f $sig_local_file ] && [ -s $sig_local_file ] && [ -f $lic_local_file ] && [ $(cat $lic_local_file | wc -l) != 0 ]; then
    DEST_DIR=/etc/dpi
    TMP_DIR=$(mktemp -d -p $DEST_DIR)
    local lic_to_tmp=$(mv -f $lic_local_file $TMP_DIR && echo 1 || echo 0)

    if [ $lic_to_tmp -eq 1 ]; then
      WriteLog "Downloaded DPI lic file moved to tmp dir! [ $TMP_DIR ]" "DEBUG"
    else
      WriteLog "Failed to move DPI lic file to tmp dir! [ $TMP_DIR ]" "ERROR"
    fi

    local sig_to_tmp=$(mv -f $sig_local_file $TMP_DIR && echo 1 || echo 0)
    if [ $sig_to_tmp -eq 1 ]; then
      WriteLog "Downloaded DPI license sig file moved to tmp dir! [ $TMP_DIR ]" "DEBUG"
    else
      WriteLog "Failed to move DPI license sig file to tmp dir! [ $TMP_DIR ]" "ERROR"
    fi

    if [ $sig_to_tmp -eq 1 ] && [ $lic_to_tmp -eq 1 ]; then
      mv -f $TMP_DIR/* $DEST_DIR
      if [ $? -eq 0 ]; then
        WriteLog "Lic files from tmp dir successfully moved to $DEST_DIR!" "DEBUG"
      else
        WriteLog "Failed to move lic files from tmp dir to $DEST_DIR!" "ERROR"
      fi
    fi
    rmdir $TMP_DIR
  else
    WriteLog "Failed to set up tmp license! [ some file are empty ]" "ERROR"
  fi

  WriteLog "Get test DPI lic FINISH" "DEBUG"
}

function IpfixSetup() {
  WriteLog "IPFIX Setup START" "DEBUG"
  local selected_interface="lo"

  EditConfig "netflow" 8
  EditConfig "netflow_dev" "${selected_interface}"
  EditConfig "netflow_full_collector" "127.0.0.1:1500"
  EditConfig "netflow_full_collector_type" 2

  EditConfig "ipfix_dev" "${selected_interface}"
  EditConfig "ipfix_tcp_collectors" "127.0.0.1:1501"

  if [ "$CentOsVersion" -ge 8 ]; then
    systemctl restart fastdpi.service
  else
    service fastdpi restart
  fi
  PrintBoldDelimeter
  WriteLog "IPFIX Setup FINISH" "DEBUG"
}

function SetupQoEStorPeriods() {
  WriteLog "Setup QoE Stor Periods START" "DEBUG"
  EditEnvFile "IPFIX_FULLFLOW_ROTATE_MINUTES[0]" 1 "/var/qoestor/backend/.env"
  EditEnvFile "IPFIX_CLICKSTREAM_ROTATE_MINUTES[0]" 1 "/var/qoestor/backend/.env"
  EditEnvFile "IPFIX_CLICKSTREAM_ROTATE_DELAY_SECONDS[0]" 4 "/var/qoestor/backend/.env"

  sh /var/qoestor/backend/app_bash/receivers_config_restart.sh
  WriteLog "Setup QoE Stor Periods FINISH" "DEBUG"
}

function InputCloudCode() {
  while read -p "Input correct Vas Cloud Company code: " code; do
    if [ ! -z "$code" ]; then
      cloud_code="${code}"
      break
    fi
  done
  WriteLog "Inputed cloud code is ${cloud_code}" "DEBUG"
}

function InputCloudToken() {
  while read -p "Input correct Vas Cloud lic token: " token; do
    if [ ! -z "$token" ]; then
      lic_token="${token}"
      break
    fi
  done
  WriteLog "Inputed cloud token is ${lic_token}" "DEBUG"
}

function CheckCloudCodeAndToken() {
  WriteLog "Check Cloud code and license token START" "DEBUG"

  WriteLog "Current VasCloud code is ${cloud_code}" "DEBUG"
  WriteLog "Current VasCloud license token is ${lic_token}" "DEBUG"

  if [ -z $cloud_code ]; then
    InputCloudCode
  fi

  if [ $cloud_code == "[CLOUD_CODE]" ]; then
    InputCloudCode
  fi

  if [ -z $lic_token ]; then
    InputCloudToken
  fi

  if [ $lic_token == "[LIC_TOKEN]" ]; then
    InputCloudToken
  fi

  WriteLog "Final VasCloud code is ${cloud_code}" "DEBUG"
  WriteLog "Final VasCloud license token is ${lic_token}" "DEBUG"

  WriteLog "Check Cloud code and license token FINISH" "DEBUG"
}

function AskForLicense() {
  if [ $dpi_installed == 0 ]; then
    WriteLog "DPI is not installed!" "DEBUG"
    print_info "DPI is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    local q="Do you want to setup DPI test license? [Y/n](Yes is default) "
    lic=$(YesNoHandler "${q}" "y")
  else
    lic="y"
  fi
  WriteLog "Setup test DPI license answer is ${lic}" "DEBUG"
  case $lic in
  [Yy]*)
    CheckCloudCodeAndToken
    GetTestLic
    ProcessSetUpFastLic
    ;;
  [Nn]*) ;;
  esac
}

function ProcessSetupDpiui2Hardwares()
{
  WriteLog "Process setup Dpiui2 hardwares START" "DEBUG"

  if [ $dpiui2_installed == 0 ];then
    WriteLog "DPIUI2 is not installed, nothing to do!" "DEBUG"
    return
  fi

  if [ $qoe_installed != 0 ]; then
    php /var/www/html/dpiui2/backend/artisan add_hardware --hardware_type=qoestor --dpisu_login=qoesu
  fi

  if [ $dpi_installed != 0 ]; then
    php /var/www/html/dpiui2/backend/artisan add_hardware --hardware_type=dpi --dpisu_login=dpisu
    php /var/www/html/dpiui2/backend/artisan add_hardware --hardware_type=pcrf --dpisu_login=pcrfsu
  fi
  WriteLog "Process setup Dpiui2 hardwares FINISH" "DEBUG"
}

function ProcessInstallDpiui2()
{
  WriteLog "Process install Dpiui2 START" "DEBUG"

  if [ $dpiui2_installed != 0 ]; then
    WriteLog "DPIUI2 is already installed!" "DEBUG"
    print_info "DPIUI2 is already installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpiui2=()
    local header_dpiui2=$(print_spaces 30 "------------------ Install Dpiui2 ------------------")
    box_arr_dpiui2+=("$header_dpiui2")
    box_arr_dpiui2+=("Do you want to install dpiui2(User interface)? [Y/n](Yes is default)")
    box_arr_dpiui2+=("The VAS Experts DPI user Management Interface is designed to control the DPI using the graphical user interface.")
    print_box "${box_arr_dpiui2[@]}"

    local q="Do you want to install dpiui2? [Y/n](Yes is default) "
    dpiui2=$(YesNoHandler "${q}" "y")
  else
    dpiui2="y"
  fi

  WriteLog "INSTALL DPIUI2 answer is ${dpiui2}" "DEBUG"

  case $dpiui2 in
    [Yy]*)
      PrintLightDelimeter
      InstallDpiui2
      ;;
    [Nn]*)
      return
      ;;
  esac

  UpdateDpiui2Installed
  ProcessSetupDpiui2Hardwares

  WriteLog "Process install Dpiui2 FINISH" "DEBUG"
}

function ProcessRemoveDpiui2()
{
  WriteLog "Process remove Dpiui2 START" "DEBUG"

  if [ $dpiui2_installed == 0 ]; then
    WriteLog "DPIUI2 is not installed!" "DEBUG"
    print_info "DPIUI2 is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpiui2=()
    local header_dpiui2=$(print_spaces 30 "------------------ Remove Dpiui2 ------------------")
    box_arr_dpiui2+=("$header_dpiui2")
    box_arr_dpiui2+=("Do you want to remove dpiui2(User interface)? [y/N](No is default)")
    box_arr_dpiui2+=("The VAS Experts DPI user Management Interface is designed to control the DPI using the graphical user interface.")
    print_box "${box_arr_dpiui2[@]}"

    local q="Do you want to remove dpiui2? [y/N](No is default) "
    dpiui2=$(YesNoHandler "${q}" "n")
  else
    dpiui2="n"
  fi

  WriteLog "Remove DPIUI2 answer is ${dpiui2}" "DEBUG"

  case $dpiui2 in
    [Yy]*)
      PrintLightDelimeter
      RemoveDpiui2
      ;;
    [Nn]*)
      return
      ;;
  esac

  UpdateDpiui2Installed

  WriteLog "Process remove Dpiui2 FINISH" "DEBUG"
}

function ProcessInstallQoe()
{
  WriteLog "Process install QoE START" "DEBUG"

  if [ $qoe_installed != 0 ]; then
    WriteLog "QoE is already installed!" "DEBUG"
    print_info "QoE is already installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_qoe=()
    local header_qoe=$(print_spaces 36 "------------------ Install QoE Stor ------------------")
    box_arr_qoe+=("$header_qoe")
    box_arr_qoe+=("Do you want to install QoE Stor(Statistics Server)? [Y/n](Yes is default)")
    box_arr_qoe+=("The module is designed to collect and store Neflow and Clickstream data. Data is used to analyze QoE in DPIUI2.")
    box_arr_qoe+=("Data from the VAS Experts DPI is received on several sockets (tcp or udp) using utility designed to collect IPFIX stream data.")
    box_arr_qoe+=("The collected data is stored in the ClickHouse database.")
    print_box "${box_arr_qoe[@]}"

    local q="Do you want to install QoE Stor? [Y/n](Yes is default) "
    qoe=$(YesNoHandler "${q}" "y")
  else
    qoe="y"
  fi

  WriteLog "INSTALL QoE answer is ${qoe}" "DEBUG"
  case $qoe in
  [Yy]*)
    PrintLightDelimeter
    InstallQoEStor
    SetupQoEStorPeriods
    ;;
  [Nn]*)
    return
    ;;
  esac

  UpdateQoEInstalled
  ProcessSetupDpiui2Hardwares

  WriteLog "Process install QoE FINISH" "DEBUG"
}

function ProcessRemoveQoe()
{
  WriteLog "Process remove QoE START" "DEBUG"

  if [ $qoe_installed == 0 ]; then
    WriteLog "QoE is not installed!" "DEBUG"
    print_info "QoE is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_qoe=()
    local header_qoe=$(print_spaces 36 "------------------ Remove QoE Stor ------------------")
    box_arr_qoe+=("$header_qoe")
    box_arr_qoe+=("Do you want to remove QoE Stor(Statistics Server)? [y/N](No is default)")
    box_arr_qoe+=("The module is designed to collect and store Neflow and Clickstream data. Data is used to analyze QoE in DPIUI2.")
    box_arr_qoe+=("Data from the VAS Experts DPI is received on several sockets (tcp or udp) using utility designed to collect IPFIX stream data.")
    box_arr_qoe+=("The collected data is stored in the ClickHouse database.")
    print_box "${box_arr_qoe[@]}"

    local q="Do you want to remove QoE Stor? [y/N](No is default) "
    qoe=$(YesNoHandler "${q}" "n")
  else
    qoe="n"
  fi

  WriteLog "REMOVE QoE answer is ${qoe}" "DEBUG"
  case $qoe in
  [Yy]*)
    PrintLightDelimeter
    RemoveQoEStor
    ;;
  [Nn]*)
    return
    ;;
  esac

  UpdateQoEInstalled

  WriteLog "Process remove QoE FINISH" "DEBUG"
}

function DpiFinalMessage()
{
   WriteLog "Process print DPI final message START" "DEBUG"

  local filename_lic="/etc/dpi/fastdpi.lic"

  box_arr=()
  box_arr_ru=()

  if [ -f $filename_lic ] && [ $(cat $filename_lic | wc -l) != 0 ]; then
    box_arr+=("DPI Test license installed!")
    box_arr_ru+=("Установлена тестовая лицензия!")
    WriteLog "DPI Test license installed!" "DEBUG"
  else
    box_arr+=("No DPI License file! [ ${filename_lic} is empty ]")
    box_arr_ru+=("Нет файла лицензии DPI ! [ ${filename_lic} пустой ]")
    WriteLog "No DPI License file! [ ${filename_lic} is empty ]" "ERROR"
  fi

  box_arr+=("")
  box_arr_ru+=("")

  IFS="$SAVE_IFS"
  msg=$'Default connection(s):'

  WriteLog "Bridges list:" "DEBUG"
  box_arr+=("${msg}")
  box_arr_ru+=("Подключение стандартное:")
  for bridge in "${bridges[@]}"; do
    box_arr+=(" * (port inside the network) ${bridge} (port outside the network)")
    box_arr_ru+=(" * (порт внутрь сети) ${bridge} (порт наружу сети)")

    WriteLog " * ${bridge}" "DEBUG"
  done

  box_arr+=("")
  box_arr_ru+=("")
  box_arr+=("~# lspci|grep Eth :")
  box_arr_ru+=("~# lspci|grep Eth :")
  WriteLog "Interfaces list:" "DEBUG"

  while read line; do
    if ! [[ -z $line ]]; then

      line=$(RemoveExtraSpaces "${line}")
      box_arr+=(" * ${line} ;")
      box_arr_ru+=(" * ${line} ;")
      WriteLog " * ${line} ;" "DEBUG"
    fi
  done <<< $(lspci|grep Eth)

  box_arr+=("")
  box_arr_ru+=("")
#  box_arr+=("Link statuses:")
#  WriteLog "Link statuses:" "DEBUG"

  box_arr+=("You can check the links statuses with the command:")
  box_arr+=("~# fdpi_cli dev xstat|grep --no-group-separator -B1 \"Link status\"|paste - -|sort")

  box_arr_ru+=("Проверить состояние линков можно командой:")
  box_arr_ru+=("~# fdpi_cli dev xstat|grep --no-group-separator -B1 \"Link status\"|paste - -|sort")

#  while read line; do
#    if ! [[ -z $line ]]; then
#      line=$(RemoveExtraSpaces "${line}")
#      box_arr+=(" * ${line} ;")
#      WriteLog " * ${line} ;" "DEBUG"
#    fi
#  done <<< $(fdpi_cli dev xstat|grep --no-group-separator -B1 "Link status"|paste - -|sort)


  box_arr+=("")
  box_arr_ru+=("")

  print_box_without_borders_y "${box_arr[@]}"
#  PrintLightDelimeter
  print_box_without_borders_y "${box_arr_ru[@]}"

   WriteLog "Process print DPI final message FINISH" "DEBUG"
}

function ProcessSetUpFastLic()
{
  WriteLog "Process set up fastlic START" "DEBUG"

  if [ $dpi_installed == 0 ]; then
    WriteLog "DPI is not installed!" "DEBUG"
    print_info "DPI is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpi=()
    local header_dpi=$(print_spaces 40 "------------------ Set up FastLic Service ------------------")
    box_arr_dpi+=("$header_dpi")
    box_arr_dpi+=("Do you want to set up FastLic Service? [Y/n](Yes is default)")
    box_arr_dpi+=("Service for automatic DPI license updating.")
    print_box "${box_arr_dpi[@]}"
    local q="Do you want to set up FastLic Service? [Y/n](Yes is default) "
    yn=$(YesNoHandler "${q}" "y")
  else
    yn="y"
  fi

  WriteLog "Set up FastLic Service answer is ${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    local uri=$(echo $cloud_api | base64 --decode)
    local folder="/var/fastlic"
    local file="${folder}/fastlic.sh"

    if [ ! -d $folder ];then
      mkdir $folder
      chmod -R 0777 $folder
    fi

    local req=$(curl -o $file -X GET -k -O $uri$cloud_code"/lic_script/"$lic_token --silent --write-out "%{http_code}\n")


    # wget -O $file $uri$cloud_code"/lic_script/"$lic_token

    if ! [[ -f $file ]] && [[ $req -eq 200 ]]; then
      WriteLog "Failed to set up FastLicService! (failed to download script file)" "[ERROR]"
    else
      local is_set_up=$(crontab -l 2>/dev/null | grep -i "${file}" | wc -l)
      if [ $is_set_up == 0 ];then
        local crontab_file=$SCRIPT_DIR/crontab.txt
        crontab -l > $crontab_file 2>/dev/null
        local cron_entry="0 * * * * sh ${file} >> /dev/null 2>&1"
        echo "${cron_entry}" >> $crontab_file
        crontab $crontab_file 2>/dev/null
        if [ -f $crontab_file ]; then
          rm -f $crontab_file
        fi
      else
        WriteLog "Failed to set up FastLicService! (script is already installed)" "[ERROR]"
      fi
    fi
    ;;
  esac


  WriteLog "Process set up fastlic FINISH" "DEBUG"
}

function ProcessByPassActions()
{
  WriteLog "Process ByPass action START" "DEBUG"
  local for="$1"
  local action="$2"
  WriteLog "ByPass action for ${for} is ${action}" "DEBUG"

  bpctl_util all $for $action

  WriteLog "Process ByPass action FINISH" "DEBUG"
}

function ProcessInstallByPassTool()
{
  WriteLog "Process Install ByPass tool START" "DEBUG"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf install -y --disableexcludes=all kernel-headers
    dnf install -y --disableexcludes=all kernel-devel
    dnf groupinstall -y "Development Tools"
  else
    yum install -y --disableexcludes=all kernel-headers
    yum install -y --disableexcludes=all kernel-devel
    yum groupinstall -y "Development Tools"
  fi

  local folder="/usr/lib/bp_ctl-5.2.0.41"
  local save_file="$folder.tar.gz"

  wget -O $save_file https://data.nag.ru/Silicom/bypassJet/bp_ctl-5.2.0.41.tar.gz
  cd /usr/lib
  tar zxf $save_file
  make --directory=$folder install
  bpctl_start
  bpctl_util all get_bypass
  WriteLog "Process Install ByPass tool FINISH" "DEBUG"
}

function ProcessInstallByPassDriver()
{
  WriteLog "Process Install ByPass driver START" "DEBUG"
  if [ "$CentOsVersion" -ge 8 ]; then
    dnf install -y --disableexcludes=all bypass-silicom
  else
    yum install -y --disableexcludes=all bypass-silicom
  fi
  WriteLog "Process Install ByPass driver FINISH" "DEBUG"
}

function ProcessByPassMenu()
{
  if [ $bypass_available == 0 ]; then
    WriteLog "ByPass available value is ${bypass_available}!" "ERROR"
    print_error "ByPass is not available for this hardware!"
    return
  fi
  menu_box=()
  local box_header=$(print_spaces 24 "-= ByPass menu =-")
  menu_box+=("$box_header")
  menu_box+=("")

  local tool_installed=1
  if [ ! $(command -v bpctl_util) ]; then
    menu_box+=(" * ByPass tool (bpctl_util) is not installed!")
    tool_installed=0
  fi

  local driver_installed=1
  if [ $(rpm -qa | grep bypass-silicom | wc -l) == 0 ];then
    menu_box+=(" * ByPass driver (bypass-silicom) is not installed!")
    driver_installed=0
  fi

  if [ $tool_installed != 0 ] && [ $driver_installed != 0 ];then
    menu_box+=("Current bypass state:")
    while read bp; do
      menu_box+=(" * ${bp}")
    done <<< $(bpctl_util all get_bypass)

    menu_box+=("")
    menu_box+=("Current bypass mode:")
    while read bp; do
      menu_box+=(" * ${bp}")
    done <<< $(bpctl_util all get_std_nic)
  fi

  menu_box+=("")

  if [ $driver_installed == 0 ];then
    menu_box+=("1. Install ByPass driver (bypass-silicom);")
  else
    menu_box+=("1. Install ByPass driver (bypass-silicom) - Already installed;")
  fi

  if [ $tool_installed == 0 ];then
    menu_box+=("2. Install ByPass tool (bpctl_util);")
  else
    menu_box+=("2. Install ByPass tool (bpctl_util) - Already installed;")
  fi

  if [ $tool_installed == 0 ] || [ $driver_installed == 0 ];then
    menu_box+=("3. Enable bypass - ByPass tool or/and driver is missing ;")
    menu_box+=("4. Disable bypass - ByPass tool or/and driver is missing ;")
    menu_box+=("5. Enable bypass mode for NICs - ByPass tool or/and driver is missing ;")
    menu_box+=("6. Disable bypass mode for NICs - ByPass tool or/and driver is missing ;")
  else
    menu_box+=("3. Enable bypass ;")
    menu_box+=("4. Disable bypass ;")
    menu_box+=("5. Enable bypass mode for NICs ;")
    menu_box+=("6. Disable bypass mode for NICs ;")
  fi

  menu_box+=("0. Go Back ;")

  print_box "${menu_box[@]}"

  read -p "Select an action: " act

  case "$act" in
    2)
      local msg="Do you want to install ByPass tool (bpctl_util)? [Y/n](Yes is default)"
      local yn=$(YesNoHandler "${msg}" "y")
      case "$yn" in
        [Yy]*)
          ProcessInstallByPassTool
        ;;
      esac
      ;;
    1)
      local msg="Do you want to install ByPass driver (bypass-silicom)? [Y/n](Yes is default)"
      local yn=$(YesNoHandler "${msg}" "y")
      case "$yn" in
        [Yy]*)
          ProcessInstallByPassDriver
        ;;
      esac
      ;;
    3)
      if [ $tool_installed == 0 ] || [ $driver_installed == 0 ];then
        WriteLog "Can't to execute selected action, ByPass driver or/and tool is not installed!" "ERROR"
      else
        local msg="Do you want to enable ByPass? [Y/n](Yes is default)"
        local yn=$(YesNoHandler "${msg}" "y")
        case "$yn" in
          [Yy]*)
            ProcessByPassActions "set_bypass" "on"
          ;;
        esac
      fi
      ;;
    4)
      if [ $tool_installed == 0 ] || [ $driver_installed == 0 ];then
        WriteLog "Can't to execute selected action, ByPass driver or/and tool is not installed!" "ERROR"
      else
        local msg="Do you want to disable ByPass? [Y/n](Yes is default)"
        local yn=$(YesNoHandler "${msg}" "y")
        case "$yn" in
          [Yy]*)
            ProcessByPassActions "set_bypass" "off"
          ;;
        esac
      fi
      ;;
    5)
      if [ $tool_installed == 0 ] || [ $driver_installed == 0 ];then
        WriteLog "Can't to execute selected action, ByPass driver or/and tool is not installed!" "ERROR"
      else
        local msg="Do you want to enable ByPass mode? [Y/n](Yes is default)"
        local yn=$(YesNoHandler "${msg}" "y")
        case "$yn" in
          [Yy]*)
            ProcessByPassActions "set_std_nic" "on"
          ;;
        esac
      fi
      ;;
    6)
      if [ $tool_installed == 0 ] || [ $driver_installed == 0 ];then
        WriteLog "Can't to execute selected action, ByPass driver or/and tool is not installed!" "ERROR"
      else
        local msg="Do you want to disable ByPass mode? [Y/n](Yes is default)"
        local yn=$(YesNoHandler "${msg}" "y")
        case "$yn" in
          [Yy]*)
            ProcessByPassActions "set_std_nic" "off"
          ;;
        esac
      fi
      ;;
    0)
      return
      ;;
    *)
      WriteLog "Selected install packages menu action is ${act} (invalid action)!" "ERROR"
      print_error "Selected install packages menu action does not exists! Try another one!"
      ;;
  esac

  ProcessByPassMenu
}

function UpdateIsByPassAvailable()
{
  WriteLog "Process check ByPass available START" "DEBUG"
  local result=0
  local length=$(lspci -v | grep -A1 Eth | grep "Silicom.*Device" | grep -v "0000" | wc -l)

  # length=1
  WriteLog "Check ByPass available result is ${length}"

  if [ $length != 0 ]; then
    result=1
  fi

  bypass_available=$result

  WriteLog "Process check ByPass available FINISH" "DEBUG"
}

function ProcessInstallAsnumBinLoader()
{
  WriteLog "Process install asnum bin loader START" "DEBUG"

  if [ $dpi_installed == 0 ]; then
    WriteLog "DPI is not installed!" "DEBUG"
    print_info "DPI is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpi=()
    local header_dpi=$(print_spaces 42 "------------------ Install asnum bin loader ------------------")
    box_arr_dpi+=("$header_dpi")
    box_arr_dpi+=("Service for automatic asnum bin updating.")
    print_box "${box_arr_dpi[@]}"
    local q="Do you want to install asnum bin loader? [Y/n](Yes is default) "
    yn=$(YesNoHandler "${q}" "y")
  else
    yn="y"
  fi

  WriteLog "Install asnum bin loader answer is ${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    local uri=$(echo $cloud_api | base64 --decode)
    uri=$(echo "$uri" | grep -o 'https://[^/]*')
    local folder="/var/asnum_bin_loader"
    local file="${folder}/asnum_bin_loader.sh"

    if [ ! -d $folder ];then
      mkdir $folder
      chmod -R 0777 $folder
    fi

    local req=$(curl -o $file -X GET -k -O "${uri}/api/asnum_bin_loader_script" --silent --write-out "%{http_code}\n")

    if ! [[ -f $file ]] && [[ $req -eq 200 ]]; then
      WriteLog "Failed to install asnum bin loader! (failed to download script file)" "[ERROR]"
    else
      local is_set_up=$(crontab -l 2>/dev/null | grep -i "${file}" | wc -l)
      if [ $is_set_up == 0 ];then
        local crontab_file=$SCRIPT_DIR/crontab.txt
        crontab -l > $crontab_file 2>/dev/null
        local cron_entry="0 * * * * sh ${file} >> /dev/null 2>&1"
        echo "${cron_entry}" >> $crontab_file
        crontab $crontab_file 2>/dev/null
        if [ -f $crontab_file ]; then
          rm -f $crontab_file
        fi
      else
        WriteLog "Failed to install asnum bin loader! (script is already installed)" "[ERROR]"
      fi
    fi
    ;;
  esac

  WriteLog "Process install asnum bin loader FINISH" "DEBUG"
}

function ProcessInstallDPI()
{
  WriteLog "Process install DPI START" "DEBUG"

  if [ $dpi_installed != 0 ]; then
    WriteLog "DPI is already installed!" "DEBUG"
    print_info "DPI is already installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpi=()
    local header_dpi=$(print_spaces 40 "------------------ Install DPI ------------------")
    box_arr_dpi+=("$header_dpi")
    box_arr_dpi+=("Do you want to install DPI? [Y/n](Yes is default)")
    box_arr_dpi+=("DPI is a platform for in-depth traffic analysis designed for the inspection and classification of packets with subsequent")
    box_arr_dpi+=("processing according to the task facing the company.")
    box_arr_dpi+=("")
    box_arr_dpi+=("This software solution that does not depend on a specific server hardware vendor and can flexibly adapt to business requirements.")
    box_arr_dpi+=("DPI provides high performance at an attractive price.")
    box_arr_dpi+=("")
    box_arr_dpi+=(" * Detection of more then 6000 protocols.")
    box_arr_dpi+=(" * Support for work patterns: \"in-line\", with asymmetry in outgoing traffic, with traffic mirroring.")
    box_arr_dpi+=(" * Installation on any equipment available to the operator.")
    box_arr_dpi+=(" * Subscriber management with dynamic IP-addressing, with multiple IP-addresses.")
    box_arr_dpi+=(" * The solution can be scaled to handle traffic up to 3.84 Tbit/s.")
    box_arr_dpi+=(" * Free testing.")
    print_box "${box_arr_dpi[@]}"

    local q="Do you want to install DPI? [Y/n](Yes is default) "
    dpi=$(YesNoHandler "${q}" "y")
  else
    dpi="y"
  fi

  WriteLog "INSTALL DPI answer is ${dpi}" "DEBUG"
  case $dpi in
  [Yy]*)
    dpi="y"
    PrintLightDelimeter

    if [ $dpi_installed == "0" ]; then
      InstallPackages
      EnableChronyd
      SelectInterfaces
      ConfigDPDKDriver
      ConfigDPI
      EditCore
    else
      UpdatePackages
    fi

    UpdateDpiInstalled
    UpdateQoEInstalled

    if [ $qoe_installed != 0 ]; then
      IpfixSetup
    fi

    AskForLicense

    if [ "$CentOsVersion" -ge 8 ]; then
      systemctl restart fastdpi.service
    else
      service fastdpi restart
    fi
    ;;
  [Nn]*)
    return
    ;;
  esac

  UpdateDpiInstalled
  ProcessSetupDpiui2Hardwares

#  ProcessInstallAsnumBinLoader

  DpiFinalMessage

  if [ $bypass_available != 0 ];then
    local bypass_msg=()

    bypass_msg+=("The cards support bypass. Don't forget to set it up!")

    print_error_box "${bypass_msg[@]}"
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local q="To complete the installation you must reboot the server. Do it now? [Y/n](Yes is default) "
    rb=$(YesNoHandler "${q}" "y")
  else
    rb="y"
  fi

  WriteLog "Reboot the server answer is ${rb}" "DEBUG"
  WriteLog "Process install DPI FINISH" "DEBUG"
  case $rb in
    [Yy]*) reboot ;;
  esac
}

function RemoveDpiConfig()
{
  print_info "REMOVE DPI CONFIG START"
  WriteLog "REMOVE DPI CONFIG START" "DEBUG"

  local config_file="/etc/dpi/fastdpi.conf"

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local q="Do you want to remove DPI config file(${config_file})? [y/N](No is default) "
    yn=$(YesNoHandler "${q}" "n")
  else
    yn="n"
  fi





  WriteLog "REMOVE DPI config answer is ${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    if ! [ -f $config_file ]; then
      WriteLog "DPI config file(${config_file}) doesn't exists!" "ERROR"
      print_error "DPI config file(${config_file}) doesn't exists!"
    else
      rm -f $config_file
      WriteLog "DPI config file(${config_file}) removed!" "DEBUG"
    fi

    local save_cfg_file="${config_file}.rpmsave"

    if ! [ -f $save_cfg_file ]; then
      WriteLog "DPI config save file(${save_cfg_file}) doesn't exists!" "ERROR"
      print_error "DPI config save file(${save_cfg_file}) doesn't exists!"
    else
      rm -f $save_cfg_file
      WriteLog "DPI config save file(${save_cfg_file}) removed!" "DEBUG"
    fi

    ;;
  esac


  WriteLog "REMOVE DPI CONFIG FINISH" "DEBUG"
  print_info "REMOVE DPI CONFIG FINISH"
}

function RemoveFastLicService()
{
  print_info "REMOVE FastLic service START"
  WriteLog "REMOVE FastLic service START" "DEBUG"

  local crontab_file=$SCRIPT_DIR/crontab.txt
  crontab -l | grep -v "fastlic.sh" > $crontab_file 2>/dev/null
  crontab $crontab_file 2>/dev/null
  rm -f $crontab_file

  print_info "REMOVE FastLic service FINISH"
  WriteLog "REMOVE FastLic service FINISH" "DEBUG"
}

function RemoveAsnumBinLoader()
{
  print_info "REMOVE asnum bin loader START"
  WriteLog "REMOVE asnum bin loader START" "DEBUG"

  local crontab_file=$SCRIPT_DIR/crontab.txt
  crontab -l | grep -v "asnum_bin_loader.sh" > $crontab_file 2>/dev/null
  crontab $crontab_file 2>/dev/null
  rm -f $crontab_file

  print_info "REMOVE asnum bin loader FINISH"
  WriteLog "REMOVE asnum bin loader FINISH" "DEBUG"
}

function RemoveDpiLicense()
{
  print_info "REMOVE DPI LICENSE START"
  WriteLog "REMOVE DPI LICENSE START" "DEBUG"

  local lic_file="/etc/dpi/fastdpi.lic"
  local sig_file="/etc/dpi/fastdpi.sig"
  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local q="Do you want to remove DPI license? [y/N](No is default) "
    yn=$(YesNoHandler "${q}" "n")
  else
    yn="n"
  fi

  WriteLog "REMOVE DPI license answer is ${yn}" "DEBUG"
  case $yn in
  [Yy]*)
    if ! [ -f $lic_file ]; then
      WriteLog "DPI config file(${lic_file}) doesn't exists!" "ERROR"
      print_error "DPI config file(${lic_file}) doesn't exists!"
    else
      rm -f $lic_file
      WriteLog "DPI license file(${lic_file}) removed!" "DEBUG"
    fi

    if ! [ -f $sig_file ]; then
      WriteLog "DPI config file(${sig_file}) doesn't exists!" "ERROR"
      print_error "DPI config file(${sig_file}) doesn't exists!"
    else
      rm -f $sig_file
      WriteLog "DPI signature file(${sig_file}) removed!" "DEBUG"
    fi

#    RemoveAsnumBinLoader
    RemoveFastLicService
    ;;
  esac

  WriteLog "REMOVE DPI LICENSE FINISH" "DEBUG"
  print_info "REMOVE DPI LICENSE FINISH"
}

function ProcessRemoveDPI()
{
  WriteLog "Process remove DPI START" "DEBUG"

  if [ $dpi_installed == 0 ]; then
    WriteLog "DPI is not installed!" "DEBUG"
    print_info "DPI is not installed!"
    return
  fi

  if [ "$mode" == "interactive" ]; then
    PrintBoldDelimeter
    local box_arr_dpi=()
    local header_dpi=$(print_spaces 40 "------------------ Remove DPI ------------------")
    box_arr_dpi+=("$header_dpi")
    box_arr_dpi+=("Do you want to remove DPI? [y/N](No is default)")
    box_arr_dpi+=("DPI is a platform for in-depth traffic analysis designed for the inspection and classification of packets with subsequent")
    box_arr_dpi+=("processing according to the task facing the company.")
    box_arr_dpi+=("")
    box_arr_dpi+=("This software solution that does not depend on a specific server hardware vendor and can flexibly adapt to business requirements.")
    box_arr_dpi+=("DPI provides high performance at an attractive price.")
    box_arr_dpi+=("")
    box_arr_dpi+=(" * Detection of more then 6000 protocols.")
    box_arr_dpi+=(" * Support for work patterns: \"in-line\", with asymmetry in outgoing traffic, with traffic mirroring.")
    box_arr_dpi+=(" * Installation on any equipment available to the operator.")
    box_arr_dpi+=(" * Subscriber management with dynamic IP-addressing, with multiple IP-addresses.")
    box_arr_dpi+=(" * The solution can be scaled to handle traffic up to 3.84 Tbit/s.")
    box_arr_dpi+=(" * Free testing.")
    print_box "${box_arr_dpi[@]}"

    local q="Do you want to remove DPI? [y/N](No is default) "
    dpi=$(YesNoHandler "${q}" "n")
  else
    dpi="n"
  fi

  WriteLog "REMOVE DPI answer is ${dpi}" "DEBUG"
  case $dpi in
  [Yy]*)
    dpi="y"

    systemctl stop fastdpi
    systemctl disable fastdpi

    PrintLightDelimeter

    RevertInterfaceDefaultDrivers
    RevertGrub
    RemovePackages
    RemoveDpiConfig
    RemoveDpiLicense

    UpdateDpiInstalled
    ;;
  [Nn]*)
    return
    ;;
  esac

  WriteLog "Process install DPI FINISH" "DEBUG"
}

function ProcessInstallPackagesMenu()
{
  UpdateDpiInstalled
  UpdateQoEInstalled
  UpdateDpiui2Installed

  menu_box=()
  local box_header=$(print_spaces 24 "-= Install packages menu =-")
  menu_box+=("$box_header")
  menu_box+=("")

  if [ $dpiui2_installed != 0 ];then
    menu_box+=("1. Install Dpiui2(User interface) - Already installed ;")
  else
    menu_box+=("1. Install Dpiui2(User interface) ;")
  fi

  if [ $qoe_installed != 0 ];then
    menu_box+=("2. Install QoE Stor(Statistics Server) - Already installed ;")
  else
    menu_box+=("2. Install QoE Stor(Statistics Server) ;")
  fi

  if [ $dpi_installed != 0 ]; then
    menu_box+=("3. Install DPI - Already installed ;")
    menu_box+=("4. Setup DPI test license ;")
    menu_box+=("5. Setup DPI license service;")
  else
    menu_box+=("3. Install DPI ;")
    menu_box+=("4. Setup DPI test license - DPI is not installed ;")
    menu_box+=("5. Setup DPI license service - DPI is not installed ;")
  fi

  menu_box+=("6. Install all packages (Automatically) ;")

  menu_box+=("0. Go back ;")

  print_box "${menu_box[@]}"

  read -p "Select an action: " act

  case "$act" in
    1)
      ProcessInstallDpiui2
      ;;
    2)
      ProcessInstallQoe
      ;;
    3)
      ProcessInstallDPI
      ;;
    4)
      AskForLicense
      ;;
    5)
      ProcessSetUpFastLic
      ;;
    6)
      local q="Do you want to install all packages (Dpiui2(User interface), QoE Stor(Statistics Server), DPI) automatically? [Y/n](Yes is default) "
      auto=$(YesNoHandler "$q" "y")
      case $auto in
        [Yy]*)
          mode="auto"
          UpdateOS
          ProcessInstallDpiui2
          ProcessInstallQoe
          ProcessInstallDPI
          ;;
      esac
      ;;
    0)
      return
      ;;
    *)
      WriteLog "Selected install packages menu action is ${act} (invalid action)!" "ERROR"
      print_error "Selected install packages menu action does not exists! Try another one!"
      ;;
  esac

  ProcessInstallPackagesMenu
}

function ProcessRemovePackagesMenu()
{
  UpdateDpiInstalled
  UpdateQoEInstalled
  UpdateDpiui2Installed

  menu_box=()
  local box_header=$(print_spaces 24 "-= Remove packages menu =-")
  menu_box+=("$box_header")
  menu_box+=("")

  if [ $dpiui2_installed != 0 ];then
    menu_box+=("1. Remove Dpiui2(User interface); ")
  else
    menu_box+=("1. Remove Dpiui2(User interface) - Not installed ; ")
  fi

  if [ $qoe_installed != 0 ];then
    menu_box+=("2. Remove QoE Stor(Statistics Server) ;")
  else
    menu_box+=("2. Remove QoE Stor(Statistics Server) - Not installed ;")
  fi

  if [ $dpi_installed != 0 ]; then
    menu_box+=("3. Remove DPI ;")
  else
    menu_box+=("3. Remove DPI - Not installed ;")
  fi

  menu_box+=("4. Revert interface drivers to default ;")

  menu_box+=("5. Remove FastLic service ;")

  menu_box+=("0. Go back ;")

  print_box "${menu_box[@]}"

  read -p "Select an action: " act

  case "$act" in
    1)
      ProcessRemoveDpiui2
      ;;
    2)
      ProcessRemoveQoe
      ;;
    3)
      ProcessRemoveDPI
      ;;
    4)
      local q="Do you want to disable DPDK mode for interfaces? [Y/n](Yes is default) "
      dis=$(YesNoHandler "$q" "y")
      case $dis in
        [Yy]*)
          RevertInterfaceDefaultDrivers
          ;;
      esac
      ;;
    5)
      local q="Do you want to remove FastLic service? [y/N](No is default) "
      dis=$(YesNoHandler "$q" "n")
      case $dis in
        [Yy]*)
          RemoveFastLicService
          ;;
      esac
      ;;
    0)
      return
      ;;
    *)
      WriteLog "Selected remove packages menu action is ${act} (invalid action)!" "ERROR"
      print_error "Selected remove packages menu action does not exists! Try another one!"
      ;;
  esac

  ProcessRemovePackagesMenu
}

function ProcessMenu()
{
  UpdateIsByPassAvailable
  menu_box=()
  local box_header=$(print_spaces 24 "-= Main menu =-")
  menu_box+=("$box_header")
  menu_box+=("")

  menu_box+=("1. Update OS ;")
  menu_box+=("2. Install packages ;")
  menu_box+=("3. Remove packages ;")
  menu_box+=("4. Reboot server;")
  if [ $bypass_available == 0 ];then
    menu_box+=("5. Configure ByPass - NOT AVAILABLE ;")
  else
    menu_box+=("5. Configure ByPass ;")
  fi
  menu_box+=("0. Exit ;")

  print_box "${menu_box[@]}"

  read -p "Select an action: " act

  case "$act" in
    1)
      UpdateOS
      ;;
    2)
      ProcessInstallPackagesMenu
      ;;
    3)
      ProcessRemovePackagesMenu
      ;;
    4)
      RebootOS
      ;;
    5)
      ProcessByPassMenu
      ;;
    0)
      exit
      ;;
    *)
      WriteLog "Selected main menu action is ${act} (invalid action)!" "ERROR"
      print_error "Selected main action does not exists! Try another one!"
      ;;
  esac

  ProcessMenu
}

function Main() {
  PrintLogo

  InitGlobalVariables

  if [[ $(id -u) -ne 0 ]] ; then
    print_error "Please run script as root"
    WriteLog "Trying to execute script not as root!" "ERROR"
    EngineerExit
  fi

  WriteLog "Starting install script" "DEBUG"

  WriteLog "Script version is ${script_version}" "DEBUG"

  WriteLog "VasCloud code is ${cloud_code}" "DEBUG"
  WriteLog "VasCloud license token is ${lic_token}" "DEBUG"


  if [ -z $mode ]; then
    mode="interactive"
  fi

  CheckInternetConnection
  CheckSystem
  EnableRepos
  InstallWget

  ProcessMenu
}

function Test() {
  InitGlobalVariables
#  if [ -z $mode ]; then
#    AskInteractive
#  fi
  CheckSystem
}

#POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
  -em | --engineer_mode)
    em="$2"
    shift
    shift
    if [ "$em" == 1 ]; then
      engineer_mode=1
    else
      engineer_mode=0
    fi
    ;;
  -c | --cloud_code)
    local_cloud_code="$2"
    shift # past argument
    shift # past value
    cloud_code="${local_cloud_code}"
    WriteLog "Set up cloud_code=${cloud_code}" "DEBUG"
    ;;
  -lt | --lic_token)
    local_lic_token="$2"
    shift
    shift
    lic_token="${local_lic_token}"
    WriteLog "Set up lic_token=${lic_token}" "DEBUG"
    ;;
  -dic | --disable_interfaces_check)
    local_disable="$2"
    shift
    shift
    disable_interfaces_check="$local_disable"
    ;;
  -dhtc | --disable_hyper_threading_check)
    local_disable="$2"
    shift
    shift
    disable_hyper_threading_check="$local_disable"
    ;;
  esac
done

# Test
Main

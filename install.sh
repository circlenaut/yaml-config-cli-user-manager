#!/usr/bin/env bash

# This script installs mgt_users.py to your PATH as mgt_users

_local_bin="$HOME/.local/bin"

function in_list () {
    local _element="$1"
    shift
    local _list=("$@")
    local _match="False"
    for _i in "${_list[@]}";
        do
            if [[ $_element = $_i ]]; then local _match="True"; fi
        done
    if [[ $_match = "True" ]]; then return 0; else return 1; fi
}

function continue_prompt () {
    declare -a _valid_yes=(
        "yes"
        "Yes"
        "YES"
        "y"
        "Y"
        "True"
        "true"
    )
    declare -a _valid_no=(
        "no"
        "No"
        "NO"
        "n"
        "N"
        "False"
        "false"
    )
    local _response=${1}
    local _proceed="False"
    while [[ $_proceed = "False" ]]
        do
            in_list $_response "${_valid_yes[@]}"
            local _return_code_valid_yes=$?
            in_list $_response "${_valid_no[@]}"
            local _return_code_valid_no=$?
            if [[ $_return_code_valid_yes = 0 ]]; then
                return 0
            elif [[ $_return_code_valid_no = 0 ]]; then
                return 1
            else
                read -p 'Invalid response, try again: ' _response
            fi
        done
}

function create_local_bin () {
    if [ ! -d $_local_bin ]; then
        echo "creating dir: $_local_bin"
        /bin/mkdir $_local_bin
        if [[ $? = 0 ]]; then return 0; else return 1; fi
    else
        return 0
    fi
}

function copy_file () {
    local _src_path=${1}
    local _dst_path=${2}
    if [ ! -f $_dst_path ]; then
        /bin/cp $_src_path $_dst_path
        if [[ $? = 0 ]]; then return 0; else return 1; fi
        /bin/chmod +x $_dst_path
        if [[ $? = 0 ]]; then return 0; else return 1; fi
    else
        echo "file exists! $_dst_path"
        return 1
    fi
}

function path_exists_in_profile () {
    local _exists="False"
    local _path=${1}
    local _export_line='export PATH=$PATH':$_local_bin
    local _profile_file="$HOME/.profile"
    while read _line; do
        if [[ "$_line" = "$_export_line" ]]; then 
            local _exists="True"; 
        fi
    done < $_profile_file    
    if [[ $_exists = "True" ]]; then return 0; else return 1; fi
}

function path_exists_in_env () {
    local _exists="False"
    local _path=${1}
    IFS=':' read -r -a _paths <<< "$PATH"
    for _p in "${_paths[@]}"
        do
            if [[ "$_p" = "$_path" ]]; then local _exists="True"; fi
        done  
    if [[ $_exists = "True" ]]; then return 0; else return 1; fi
}

function add_to_path () {
    local _new_path=${1}
    if [ -z "${PATH-}" ]; then export PATH=/usr/local/bin:/usr/bin:/bin; fi
    path_exists_in_profile $_new_path
    if [[ $? = 0 ]]; then
        echo "path exists in .profie : $_new_path"
        return 0
    elif [[ $? = 1 ]]; then
        echo "adding to path: $_local_bin"
        echo 'export PATH=$PATH':$_local_bin | /usr/bin/tee -a $HOME/.profile >/dev/null
        echo "run 'source $HOME/.profile' to activate new Path"
        return 0
    else
        return 1
    fi
}

function remove_from_path () {
    local _old_path=${1}
    local _profile_file="$HOME/.profile"
    path_exists_in_profile $_old_path
    if [[ $? = 0 ]]; then
        local _export_line='export PATH=$PATH':$_local_bin
        _n=1
        while read _line; do
            if [[ "$_line" = "$_export_line" ]]; then
                echo "removing $_old_path at line no. $_n from $_profile_file"
                sed -i "${_n}d" $_profile_file
            fi
            _n=$((_n+1))
        done < $_profile_file 
        return 0
    elif [[ $? = 1 ]]; then
        echo "path does not exists in $_profile_file: $_old_path"
        return 0
    else
        return 1
    fi
}

function install_script () {
    local _script_src_path="./mgt_users.py"
    local _script_dst_path="$HOME/.local/bin/mgt_users"
    create_local_bin
    if [[ $? = 0 ]]; then
        copy_file $_script_src_path $_script_dst_path
        if [[ $? = 0 ]]; then
            read -p 'Add to PATH? ' _response
            continue_prompt $_response
            local _return_code_continue=$?
            if [[ $_return_code_continue = 0 ]]; then add_to_path $_local_bin; fi
            echo "Script installed to: $_script_dst_path"
        else
            echo "Failed to install script"
            exit 1
        fi
    else
        exit 1
    fi
}

function uninstall_script () {
    local _script_path="$HOME/.local/bin/mgt_users"
    if [ -f $_script_path ]; then
        remove_from_path $_local_bin
        /bin/rm $_script_path
        echo "removed: $_script_path"
        if [[ $? = 0 ]]; then return 0; else return 1; fi
    else
        echo "does not exist: $_script_path"
    fi
}

while getopts iu flag
do
    case "${flag}" in
        i) 
            read -p 'Install script? ' _response
            continue_prompt $_response
            _main_return_code_continue=$?
            if [[ $_main_return_code_continue = 0 ]]; then install_script; else exit 0; fi
            break
            ;;
        u) 
            read -p 'Uninstall script? ' _response
            continue_prompt $_response
            _main_return_code_continue=$?
            if [[ $_main_return_code_continue = 0 ]]; then uninstall_script; else exit 0; fi
            break
            ;;
    esac
done

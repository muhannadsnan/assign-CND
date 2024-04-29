#!/bin/bash
# Author: Shady Alshamy
# Purpose: To execute checks using the IoC file, generate logs and a report, and upload the outputs to a central server.

# Collect parameters
DOWNLOAD_URL="$1"
UPLOAD_URL="$2"
USERNAME="$3"

### Define global variables

SECURITY_DIR="/opt/security" # Define the security directory
WORKING_DIR="$SECURITY_DIR/working" # Define the working directory

IOC_FILE="IOC-$(date +%Y%m%d).ioc" # Define the location of the IoC file
IOC_GPG_FILE="IOC-$(date +%Y%m%d).gpg" # Define the location of the signed IoC file

# Path to validation tools
IOC_TOOL="$SECURITY_DIR/bin/sha256sum"
STR_TOOL="$SECURITY_DIR/bin/grep"

# Define the location of the report file, the temporary matches log, failure log
report_name="iocreport-$(date +%Y%b%d).txt"
REPORT_FILE="$WORKING_DIR/$report_name" 
MATCHES_LOG="$WORKING_DIR/matches.log.tmp"
FAIL_LOG="$WORKING_DIR/failure.log"

# Define the error directory and error file
ERROR_DIR="$SECURITY_DIR/errors" 
ERROR_LOG="$ERROR_DIR/error-$(date +%Y%b%d).log"

# Create necessary folders if they don't exist, give them permissions, copy necessary files into them, define global variables
prepare() {
    echo -e "\n >>> SETUP & PREPARE"

    # The number of the current step, used to identify the step when an error accurs
    STEP=1
    local already_setup=true
    # Check existence of /opt/security
    if [ ! -d "$SECURITY_DIR" ]; then
        already_setup=false
        sudo mkdir $SECURITY_DIR
        # copy the PGP private & public keys inside >> verify the ioc file
        sudo cp ./shaal25790.asc /opt/security/shaal25790.asc
        sudo cp ./shaal25790_public.asc /opt/security/shaal25790_public.asc
        sudo chmod 755 $SECURITY_DIR # Read-only folder (group, public)
        # copy the SSH private & public keys inside >> ssh login to the remote server
        sudo cp ~/.ssh/id_rsa /opt/security/shaal25790.id
        sudo chown vagrant:vagrant /opt/security/shaal25790.id
        sudo chmod 600 /opt/security/shaal25790.id 
        sudo cp ~/.ssh/id_rsa.pub /opt/security/shaal25790_public.id
        echo -e "CREATED FOLDER '$SECURITY_DIR', AND PERMISSIONS GIVEN."
    fi

    # Check existence of /opt/security/working
    if [ ! -d "$WORKING_DIR" ]; then
        already_setup=false
        sudo mkdir $WORKING_DIR
        sudo chmod 777 $WORKING_DIR
        echo -e "CREATED FOLDER '$WORKING_DIR', AND PERMISSIONS GIVEN."
    fi

    # Check existence of /opt/security/errors
    if [ ! -d "$ERROR_DIR" ]; then
        already_setup=false
        sudo mkdir $ERROR_DIR
        sudo chmod 777 $ERROR_DIR
        echo -e "CREATED FOLDER '$ERROR_DIR', AND PERMISSIONS GIVEN."
    fi

    # Check existence of /opt/security/bin
    if [ ! -d "$SECURITY_DIR/bin" ]; then
        already_setup=false
        sudo mkdir $SECURITY_DIR/bin
        sudo chmod 777 $SECURITY_DIR/bin
        echo -e "CREATED FOLDER '$SECURITY_DIR/bin', AND PERMISSIONS GIVEN."
        # Copy the validation tools into the /opt/security/bin directory
        cp /usr/bin/sha256sum "$SECURITY_DIR/bin"
        cp /usr/bin/grep "$SECURITY_DIR/bin"
    fi

    # Now, create the report and temporary log, this also empty the files (in case they already had data)
    > $REPORT_FILE
    > $MATCHES_LOG
    > $FAIL_LOG
    > $ERROR_LOG

    if [ $already_setup == true ]; then
        echo -e "PREPARE ALREADY DONE.\n"
    else 
        echo -e " >>> SCRIPT PREPARE COMPLETE\n"
    fi
}


# Print a message to both STDOUT & files 
log_report() { 
    # local error_msg="$1"
    # local more_files="$2"
    # # Check if more_files is empty
    # if [[ -n "$more_files" ]]; then
    #     echo -e "$error_msg" | tee -a "$REPORT_FILE" "$more_files"
    # else
    #     echo -e "$error_msg" | tee -a "$REPORT_FILE"
    # fi
    if [[ -z "$2" ]]; then
        more_files=""
    else
        more_files="$2"
    fi
    echo -e "$1" | tee -a $REPORT_FILE $more_files # output to both stdout and file (append to file on each log, resets at the beginning of script)
}

# Log an error to specify the step, using the previous function. Takes a number of step 'Sx'
log_error_step() {
    log_report "FAILED S${STEP} - $(hostname) $(date +'%Y%m%d-%H:%M')" "$ERROR_LOG"
}

# Set the trap to catch errors and execute a specific function when an error occurs.
trap log_error_step ERR

# Download the IoC file
download_ioc() {
    STEP=2
    # Check if both ioc & gpg files are already present
    if [[ -f "$WORKING_DIR/$IOC_FILE" ]] && [[ -f "$WORKING_DIR/$IOC_GPG_FILE" ]]; then
        log_report "\n >>> IOC FILE AND IT'S GPG FILE ALREADY DOWNLOADED.\n"
    else
        # At least one of the files is missing
        # Check if we have IOC file 
        if [[ ! -f "$WORKING_DIR/$IOC_FILE" ]]; then
            # Check if the URL starts with https
            if [[ $DOWNLOAD_URL != https* ]]; then
                log_report "ERROR: The URL must start with https." "$ERROR_LOG"
                log_error_step # log error for this Step
                exit 1
            fi

            log_report "DOWNLOADING IOC FILE FROM URL: $DOWNLOAD_URL/$IOC_FILE \n"

            # Download the IoC file & the signed file in the working directory
            sudo wget -O "$WORKING_DIR/$IOC_FILE" "$DOWNLOAD_URL/$IOC_FILE"

            # Check if IOC-file download failed
            if [[ $? -ne 0 ]]; then
                log_report "ERROR: Failed to download the IoC file." "$ERROR_LOG"
                log_error_step # log error for this Step
                sudo rm -rf "$WORKING_DIR/$IOC_FILE" # in case wget creates an empty file
                exit 1
            fi
            log_report "\n > IOC FILE DOWNLOADED..\n"
        fi


        # Check if we have IOC-GPG file 
        if [[ ! -f "$WORKING_DIR/$IOC_GPG_FILE" ]]; then
            log_report "DOWNLOADING IOC-GPG FILE FROM URL: $DOWNLOAD_URL/$IOC_GPG_FILE \n"

            sudo wget -O "$WORKING_DIR/$IOC_GPG_FILE" "$DOWNLOAD_URL/$IOC_GPG_FILE"
            
            # Check if IOC-GPG-file download failed
            if [[ $? -ne 0 ]]; then
                log_report "ERROR: Failed to download the IoC-GPG file." "$ERROR_LOG"
                log_error_step # log error for this Step
                sudo rm -rf "$WORKING_DIR/$IOC_GPG_FILE" # in case wget creates an empty file
                exit 1
            fi

            log_report "\n > GPG FILE DOWNLOADED..\n"
        fi
    fi    
}

# Check the integrity of the IoC file, and exit if invalid
check_ioc_file_integrity() {
    STEP=3
    # import the public key so that it is used to the verification
    gpg --import "$SECURITY_DIR/${USERNAME}_public.asc"
    # verify that the signature of the ioc file
    gpg --verify "$WORKING_DIR/$IOC_GPG_FILE" "$WORKING_DIR/$IOC_FILE"

    # Verification failed? log error & exit
    if [[ $? -ne 0 ]]; then
        log_report "ERROR: CHECK OF IOC FILE INTEGRITY FAILED." "$ERROR_LOG"
        log_error_step # log error for this Step
        exit 1
    fi
}

# Check if datestamp matches the filename, and exit if invalid
check_datestamp() {
    STEP=4
    # Get datestamp inside IoC file
    second_line=$(sed -n '2p' "$WORKING_DIR/$IOC_FILE" | tr -d '\r\n')
    # Get file name without path 
    base_name=$(basename "$WORKING_DIR/$IOC_FILE") 
    # Get datestamp in file name
    date_stamp=${base_name:4:8} 
    # datestamp in file name matches the one in IoC file ?
    if [[ "$date_stamp" == "$second_line" ]]; then 
        log_report "Datestamp '$date_stamp' validation OK"
    else
        log_report "WARN: Datestamp does not match the value in the IoC file." "$ERROR_LOG"
        log_error_step # log error for this Step
        exit
    fi
}

# Validate the tools by, and exit if invalid
check_tool() {
    STEP=5
    # Define the expected hash and the tool based on parameters
    expected_hash=$1
    tool=$2
    # Calculate the SHA-256 hash of the IoC file
    local actual_hash=$(sha256sum $tool | awk '{ print $1 }')

    # Check if the actual hash matches the expected hash
    if [[ $actual_hash != $expected_hash ]]; then
        log_report "ERROR: INVALID TOOL $tool" "$ERROR_LOG"
        log_error_step # log error for this Step
        exit 1
    fi
    log_report "\n > TOOL '$tool' CHECK OK.\n"
}

# Search for files that have the given hash in the given directory, and log warning if found
check_ioc() {
    STEP=7
    # Define the hash and directory based on parameters
    hash=$1
    directory=$2
    # inside the directory, check sha256hash of all files if any matches the given hash, excluding files in directories /proc, /run and /sys
    output=$(sudo find "$directory" -type f -not -path "/proc/*" -not -path "/run/*" -not -path "/sys/*" -exec "$IOC_TOOL" {} \; | "$STR_TOOL" "$hash")
    # If the hash was found, log a warning
    if [[ $? -eq 0 ]]; then 
        log_report "WARN: IOCHASHVALUE '$hash' found in '$(sha256sum $output | awk '{ print $2 }')'" "$MATCHES_LOG" "$ERROR_LOG"
    fi
}

# Search for files that have the given string in the given directory
check_str() {
    STEP=7
    # Define str and directory based on parameters
    str=$1
    directory=$2
    # Check if the STR is found in on of the files in the corresponding directory
    sudo find "$directory" -type f -exec "$STR_TOOL" -E -l "$str" {} \; | while read -r filename
    do
        log_report "WARN: STRVALUE '$str' found in '$filename'" "$MATCHES_LOG" "$ERROR_LOG"
    done
}

# All the checkings here
do_checks() {
    # Check the integrity of the IoC file
    # check_ioc_file_integrity








    # Check the datestamp of ioc file
    check_datestamp

    # Read the IoC file line by line
    while IFS= read -r line; do
        if [[ $line != \#* ]]; then # Ignore comments
            IFS=' ' read -r -a array <<< "$line" # Split the line into an array
            log_report "LINE: '$line'"

            # Check the integrity of the validation tool
            if [[ ${array[0]} == "VALIDATE" ]]; then
                # Take the first part of the line defining the hash
                local hash=$(echo "${array[1]}" | tr -d '\r\n') # trim the new line in case exists
                check_tool $hash "$IOC_TOOL"
            fi

            # Check the integrity of the strcheck tool
            if [[ ${array[0]} == "STRCHECK" ]]; then
                # Take the first part of the line defining the hash
                local hash=$(echo "${array[1]}" | tr -d '\r\n') # trim the new line in case exists
                check_tool "$hash" "$STR_TOOL"
            fi

            # Check if the line starts with IOC
            if [[ ${array[0]} == "IOC" ]]; then
                # Get hash and directory from the line
                local hash=$(echo "${array[1]}" | tr -d '\r\n') # trim the new line in case exists
                local directory=$(echo "${array[2]}" | tr -d '\r\n')
                
                # LET's GO! Check if the hash appears in the specified directory
                if [[ -d "$directory" ]]; then
                    check_ioc $hash $directory
                else
                    log_report "Directory '$directory' does not exist." "$ERROR_LOG"
                fi
            fi

            # Check if the line starts with STR
            if [[ ${array[0]} == "STR" ]]; then 
                local str=${array[1]}
                local directory=$(echo "${array[2]}" | tr -d '\r\n')

                # Check if the string appears in the specified directory
                if [[ -d "$directory" ]]; then
                    check_str $str $directory
                else
                    log_report "Directory '$directory' does not exist." "$ERROR_LOG"
                fi
            fi
        fi
    done < "$WORKING_DIR/$IOC_FILE"
    log_report "\n >>> IOC CHECKING FINISHED.\n\n"
}

check_noexec() {
    # Define the directories to check
    dirs=("/var/www/images" "/var/www/uploads")

    # Loop over the directories
    for dir in "${dirs[@]}"; do
        # Directory exists
        if [ -d "$dir" ]; then
            log_report "Check noexec for dir: $dir"
            # Check if the directory is mounted with noexec option
            if mount | grep "$dir" | grep -q 'noexec'; then
                log_report "$dir is mounted with noexec option"
            else
                log_report "WARNING: $dir is not mounted with noexec option" "$ERROR_LOG"
                log_report "Correcting the issue..."
                # Remount the directory with noexec option
                sudo mount -o remount,noexec "$dir"
                # Log messages if succeeds or fails
                if [ $? -eq 0 ]; then
                    log_report "Successfully remounted $dir with noexec option" "$ERROR_LOG"
                else
                    log_report "Failed to remount $dir with noexec option" "$ERROR_LOG"
                fi
            fi
        else
            log_report "Directory $dir does not exist" "$ERROR_LOG"
        fi
    done

    # Output the system configuration for mounting filesystems
    log_report "\n > System configuration for mounting filesystems:\n"
    log_report "$(cat /etc/fstab)"
}

# Collect system information
collect_sys_info() {
    STEP=9
    # Get currently listening ports (with no DNS/port name resolution)
    listening_ports=$(ss -tuln | awk '{print $5}')

    # Get current firewall rules (with no DNS/port name resolution)
    firewall_rules=$(sudo iptables -L)

    # Loop through all packages that have installed files in these directories '/sbin, /bin, /usr/sbin, /usr/bin and /usr/lib'
    # Then extract the package names, and remove duplicates
    pkg=$(for pkg in $(sudo dpkg -S /sbin /bin /usr/sbin /usr/bin /usr/lib | cut -d: -f1 | tr -d ',' | sort -u); do
        sudo dpkg -V $pkg # checks each package
    done)
    
    log_report "\n > VALIDATE HASHES OF FILES INSTALLED IN /sbin, /bin, /usr/sbin, /usr/bin AND /usr/lib\n"
    log_report "$pkg" "$FAIL_LOG"

    # Report files in /var/www (and subdirectories) that have been created in the last 48 hours
    new_files=$(find /var/www -type f -ctime -2)

    # List any SUID/GID files in the same path regardless of modification time
    suid_gid_files=$(sudo find /var/www \( -perm -4000 -o -perm -2000 \))

    # Ensure that file systems mounted on /var/www/images and /var/www/uploads are set as non-executable (i.e. scripts cannot run from them)
    # If not, this should be corrected and a warning issues to STDOUT and the report, along with a copy of the system configuration for mounting filesystems
    log_report "\n > CHECK DIRECTORIES /var/www/images AND /var/www/uploads ARE NON_EXECUTABLE\n"
    check_noexec    
} 

# Generate a report
generate_report() {
    # Call the collect_sys_info function to collect system information
    collect_sys_info

    STEP=10
    # Write the collected information to the report file
    log_report " >>> COLLECT SYSTEM INFORMATION:\n"
    log_report " > Listening Ports:"
    log_report "$listening_ports"
    log_report " > Firewall Rules:"
    log_report "$firewall_rules"
    log_report " > New Files:"
    log_report "$new_files"
    log_report " > SUID/GID Files:"
    log_report "$suid_gid_files"

    log_report "\n >>> GENERATE, COMPRESS & SIGN THE REPORT."

    # S10: The generated files must be included with the text report into an appropriate archive file called hostname-tth-yyymmmdd.tgz. 
    # There must be a detached gpg signature generated before copying both to a remote system 

    # Define the name of the archive file
    report_archive_name="$(hostname)-tth-$(date '+%Y%b%d').tgz"
    # Define the path to the archive
    REPORT_TGZ="$WORKING_DIR/$report_archive_name"

    # Create the tgz archive
    tar -czf $REPORT_TGZ $REPORT_FILE
    log_report "\n > ARCHIVE '$REPORT_TGZ' CREATED.\n"

    # Define the key ID to use for validation
    key_id="tht2023@tht.noroff.no"

    # Sign the tgz-file, Generate a detached GPG signature
    gpg --import "$SECURITY_DIR/${USERNAME}.asc"
    gpg --batch --yes --output "${REPORT_TGZ}.sig" --detach-sign "$REPORT_TGZ"
    
    # Check if the signature fails
    if [[ $? -ne 0 ]]; then
        log_report "ERROR: Failed to sign the tgz archive '$REPORT_TGZ'" "$ERROR_LOG"
        log_error_step # log error for this Step
    else 
        log_report "\n > DETACHED GPG SIGNATURE '${REPORT_TGZ}.sig' CREATED.\n"
    fi
}

# Upload outputs to a server
upload_outputs() {
    STEP=11
    # Define the path to upload directory on the remote server 
    UPLOAD_LOCATION="/var/www/html/submission/$(hostname)/$(date +%Y)/$(date +%m)"
    # Define the ssh key file
    ssh_identity_file="$SECURITY_DIR/${USERNAME}.id"

    # Upload the tgz-file to the server
    rsync -avz -e "ssh -i $ssh_identity_file" "$REPORT_TGZ" "${REPORT_TGZ}.sig" "${USERNAME}@${UPLOAD_URL}:${UPLOAD_LOCATION}"

    # Check if the upload fails
    if [[ $? -ne 0 ]]; then
        log_report "ERROR: Failed to upload the outputs to the server" "$ERROR_LOG"
        log_error_step # log error for this Step
        exit 1
    else
        log_report "\n >>> OUTPUT UPLOADED SUCCESSFULLY.\n"
        # Proceed to the next step, validate the upload on the remote server
        validate_backup
    fi
}

# Validate the backup on the remote server
validate_backup() {
    STEP=12
    # Define name of the signature for the report archive  
    report_signature="$(hostname)-tth-$(date '+%Y%b%d').tgz.sig"

    # Validate the backup on the remote server using the report signature
    ssh -i "$ssh_identity_file" "${USERNAME}@${UPLOAD_URL}" "gpg --import ${SECURITY_DIR}/${USERNAME}_public.asc; gpg --verify ${UPLOAD_LOCATION}/${report_signature} ${UPLOAD_LOCATION}/$report_archive_name"

    # Check if validation fails
    if [[ $? -ne 0 ]]; then
        log_report "ERROR: Failed to validate the backup on the remote server" "$ERROR_LOG"
        log_error_step # log error for this Step
        exit 1
    fi

    # Backup validation OK
    log_report "\nTTH IoC Check for $(hostname) $(date +'%Y%m%d-%H:%M') OK \n"
    log_report "\n >>> BACKUP VALIDATED.\n\n"
}

# Clean up after the script. Remove most of the files produced by the script, like the report, report archive, report signature. Also the IOC file and it's GPG file
# Remove the MATCHES.log & FAILURE.log since they are included in the report anyway.
#   I don't understand why it was required to create them in the first place, if we remove them and no one is gonna read them... 
#   Anyway, the specification calls them temporary files in the working directory, so they must be swapped
# SSH keys & PGP keys should stay for future execution of the script. The same is for validation tools.
clean_up() {
    # Remove files
    sudo rm -f "$REPORT_FILE" "$REPORT_TGZ" "${REPORT_TGZ}.sig" $WORKING_DIR/* 

    # Check removing ok
    if [[ $? -ne 0 ]]; then
        echo -e "ERROR: Clean up not complete. Files to remove: \n $REPORT_FILE \n $REPORT_TGZ \n ${REPORT_TGZ}.sig \n $WORKING_DIR/*" "$ERROR_LOG"
    else
        echo -e "REMOVED FILES: \n $REPORT_FILE \n $REPORT_TGZ \n ${REPORT_TGZ}.sig \n $WORKING_DIR/*"
    fi

    # Archive Error-file, then removed
    tar -czf "${ERROR_LOG}.tgz" "$ERROR_LOG"
    # Remove error log
    sudo rm -f "$ERROR_LOG"

    # Check removing ok
    if [[ $? -ne 0 ]]; then
        echo -e "ERROR: Clean up not complete." "$ERROR_LOG"
    else
	    echo -e "\n >>> CLEAN UP COMPLETE.\n\n"
    fi
}

# shaal25790@stud.noroff.no # shady@noroff2023 # tht2023@tht.noroff.no
# cd /code && ./tth-IOC.sh "https://shady-cnd.no" "shady-logs.no" "shaal25790"

# Main script execution
echo -e "\n\n|||||||||||||||||||||||||||| MAIN EXECUTION ||||||||||||||||||||||||||||\n"
prepare

echo -e "\n================ download_ioc =================\n"
download_ioc

echo -e "\n================ do_checks =================\n"
do_checks 

echo -e "\n================ generate_report =================\n"
generate_report

echo -e "\n================ upload_outputs =================\n"
upload_outputs

echo -e "\n================ clean_up =================\n"
clean_up

echo -e "\n================ ALL DONE ! =================\n"

#!/bin/bash

# Check if filename argument is provided
if [ $# -eq 0 ]; then
  echo "Usage: $0 <json_file>"
  exit 1
fi

# Extract relevant fields using jq from the provided JSON file
jq_query='.[] | select(.event.PROCESS_ID == 3532) | {
  USER_NAME: .event.USER_NAME,
  ts: .ts,
  event_id: .routing.event_id,
  int_ip: .routing.int_ip,
  COMMAND_LINE: .event.COMMAND_LINE,
  FILE_PATH: .event.FILE_PATH,
  HASH: .event.HASH,
  PROCESS_ID: .event.PROCESS_ID,
  PARENT_COMMAND_LINE: .event.PARENT.COMMAND_LINE,
  PARENT_FILE_PATH: .event.PARENT.FILE_PATH,
  PARENT_HASH: .event.PARENT.HASH,
  PARENT_PROCESS_ID: .event.PARENT.PROCESS_ID
}'

# Execute jq query and store the output
data=$(jq -r "$jq_query" "$1")

# Print formatted output
echo "================================="
echo "ATTENTION: A \"NEW_PROCESS\" alert has been triggered on \"$(echo "$data" | jq -r '.USER_NAME')\""
echo
echo "Alert Details:"
echo "Time: \"$(echo "$data" | jq -r '.ts')\""
echo "Event ID: \"$(echo "$data" | jq -r '.event_id')\""
echo "Endpoint IP (Internal): \"$(echo "$data" | jq -r '.int_ip')\""
echo
echo "Child Process Details:"
echo "Command-Line: \"$(echo "$data" | jq -r '.COMMAND_LINE')\""
echo "File Path: \"$(echo "$data" | jq -r '.FILE_PATH')\""
echo "SHA256: \"$(echo "$data" | jq -r '.HASH')\""
echo "Process ID: \"$(echo "$data" | jq -r '.PROCESS_ID')\""
echo
echo "Parent Process Details:"
echo "Command-Line: \"$(echo "$data" | jq -r '.PARENT_COMMAND_LINE')\""
echo "File Path: \"$(echo "$data" | jq -r '.PARENT_FILE_PATH')\""
echo "SHA256: \"$(echo "$data" | jq -r '.PARENT_HASH')\""
echo "Process ID: \"$(echo "$data" | jq -r '.PARENT_PROCESS_ID')\""
echo "================================="

# Update this file to run your own code
#!/bin/bash
###
# THIS IS ANOTHER WAY OF EXECUTING THE GOLANG CODE
###
# go build main.go

# # Execute the compiled Go program (assuming successful compilation)
# if [ $? -eq 0 ]; then  
#     ./main 
# else
#     echo "Compilation failed."
# fi
###
# THIS IS ANOTHER WAY OF EXECUTING THE PYTHON CODE
# python3 pys_script.py
###
###
# LETS LOOK AT ANOTHER WAY TO RUN OUR GO SCRIPT
# THIS BASICALLY RUNS ANY GO FILE FROM WITHIN THE ROOT DIRECTORY. IF OUR GO FILE IS IN A SUBDIRECTORY, WE CAN USE THE FOLLOWING COMMAND
# go run -race  ./path/to/your/file.go $@ 
# OR
# # Navigate to the directory 
# cd ./path/to/your/go/code 

## Compile and run with the race detector
# go run -race . $@ 
# with the $@, any arguments passed to the script will be passed to the go run
go run -race . $@

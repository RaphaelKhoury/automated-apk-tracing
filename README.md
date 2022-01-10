# Automated APK tracing using a container

This is a script designed to automate the generation of trace of Android, apk-bundled apps. APKs are individually tested by installing them on a docker-contained Android Emulator and tracing the result of random-generated inputs by monkey.

This is designed to test both benign software and malware. The security and isolation is provided by both the use of emulation and by having the emulator run in a container.

The script will generate a database of the apk details as well as traces log files.

# Dependencies

This script requires docker to be properly installed (it should run WITHOUT sudo).

The android debug bridge (adb) package is also required.

# Usage

Read all of this before starting the script.

Check the configurations in config.txt, modify as needed.

The expected format of the source directories is important and will break the script if not respected. The source directories should contain subfolders, the name of these subfolders will be the indicated source of the apks. All files in these subfolders will be treated as apks, so don't leave anything else around here.
Example :

    /apks/malware

        -> /cicmaldroid/
            -> a.apk
            -> b.apk
            ...
            
        -> /unspecified/
            -> d.apk 
            ...

The CURATED_APK_DIRECTORY should be empty when the script is first started. Else you will probalby break the script and lose your data.

The script will pull the image required from the Google repos the first time it is started. Each trace can be quite long. You can stop the script  with CTR-C, you will only loose the current trace. If you stop the script before the tracing phase (before “… preparing data done”) you should delete the content of the curated apk directory as well as the database files. If the script is restarted it will skip all previously done apk.

Launch the script trace.sh


# Database

*fileCorrespondance.csv* holds the correspondance between input files (apks) and Unique Package Identifiers ( UPI ).
Each file is renamed using a UPI, it is the SHA256 sum of the file.
The table is as follow :

sourceFileRelativeToScript;UPI;source;

*packageInfo.csv* holds the metadata info about each package.
The table is as follow : 
UPI;malware;packageName;sdkVersion;targetSDKVersion;applicationLabel;permissions;features

The actual permissions and features that are checked for are listed in features.txt and permissions.txt. You can remove items from these files to reduce the size of this table.

*logsCorrespondance.csv* holds the correspondance between UPI and logs produced.
The table is as follow
UPI;monkeyInputSize;eventsActuallySent;timedOut;monkeySeed;outFilesName

The output files will be outFilesName.monkdata and outFilesName.trace.
The app can crash before all requested input are sent, in this case the eventsActuallySent will be smaller than monkeyInputSize. It is fuzzing after all, and some apps are not robust enough to handle it.
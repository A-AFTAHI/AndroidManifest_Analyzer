#! /usr/bin/env python
import os
import sys 
import xml.dom.minidom
import requests

def manifest_analysis(source):
    #List of Android dangerous permissions
    DangPer = ['android.permission.READ_CALENDAR','android.permission.WRITE_CALENDAR','android.permission.CAMERA','android.permission.READ_CONTACTS','android.permission.WRITE_CONTACTS','android.permission.GET_ACCOUNTS','android.permission.ACCESS_FINE_LOCATION','android.permission.ACCESS_COARSE_LOCATION','android.permission.RECORD_AUDIO','android.permission.READ_PHONE_STATE','android.permission.READ_PHONE_NUMBERS','android.permission.CALL_PHONE','android.permission.ANSWER_PHONE_CALLS','android.permission.READ_CALL_LOG','android.permission.WRITE_CALL_LOG','com.android.voicemail.permission.ADD_VOICEMAIL','android.permission.USE_SIP','android.permission.PROCESS_OUTGOING_CALLS','android.permission.ANSWER_PHONE_CALLS','android.permission.BODY_SENSORS','android.permission.SEND_SMS','android.permission.RECEIVE_SMS','android.permission.READ_SMS','android.permission.RECEIVE_WAP_PUSH','android.permission.RECEIVE_MMS','android.permission.READ_EXTERNAL_STORAGE','android.permission.WRITE_EXTERNAL_STORAGE']
    keywords = ['key','Key','KEY','password']
    Buffer = open(source,'r')
    manifest = xml.dom.minidom.parse(Buffer)
    application = manifest.getElementsByTagName('application')
    #activities = manifest.getElementsByTagName('activity')
    uses_permissions = manifest.getElementsByTagName('uses-permission')
    permissions = manifest.getElementsByTagName('permission')
    intent_filters = manifest.getElementsByTagName('intent-filter')
    meta_datas = manifest.getElementsByTagName('meta-data')
    services = manifest.getElementsByTagName('service')
    providers = manifest.getElementsByTagName('provider')
    receivers = manifest.getElementsByTagName('receiver')
    uses_sdks = manifest.getElementsByTagName('uses-sdk')
    application_permission = None #define the general permission of the app declared in <application> 
    targetSdkVersion = None
    
    
    #Analysing Application's parameters"
    for app in application:
        
        if app.getAttribute("android:debuggable")=="true":
            des="Allow the application to generate debugging messages."
            imp ="allowing application debugging leads to application critical information leaking."
            recom = "you must set android:debuggable parameter to false in AndroidManifest file."
            state = 'ERROR'
            print "\nparameter : Debugging\nvalue : True\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)
            
        else:
            des="The application does not generate debugging Messages."
            state = 'Good'
            print "\nparameter : Debugging\nvalue : False\ndescription %s\nstatus : %s\n"%(des,state)
            

        if app.getAttribute("android:permission"): 
            application_permission = app.getAttribute("android:permission")
        if app.getAttribute("android:allowBackup") == "true":
            des="Allowing the application to create and restore a copy of its internal data."
            imp = "generating the applications backup increase the possibility of user data leakge."
            recom ="AllowBackup parameter must be set to false in AndroidManifest file."
            state = 'ERROR'
            print "\nparameter : backup\nvalue : True\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)
            
        else:
            des="The application does not create or restore a copy of its internal data."
            state = 'Good'
            print "\nparameter : backup\nvalue : False\ndescription %s\nstatus : %s\n"%(des,state)
        
    #Analysing application's uses-permissions
    for usesper in uses_permissions:
        value = usesper.getAttribute("android:name")
        if value == "android.permission.WRITE_EXTERNAL_STORAGE":
            des=" This permission Allows the application to write,modify or delete the contents of the SD card"
            imp = "Data stored in extrnal storage can be accessed by any application with read access or modified by any application with write access, this  may violate data confidentiality and integrity."
            recom = "it is highly recommended to use internal storage."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_EXTERNAL_STORAGE":
            des="This permission Allows the application to read the contents of the SD card."
            imp = "This permission allows the application to read other applications data stored in the SD card which violate data confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.RECEIVE_MMS":
            des="This permission Allows the application to monitor incoming MMS messages."
            imp = "MMS messages may contain user personal data. Using this permission may lead to violate data confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.RECEIVE_WAP_PUSH":
            des="This permission Allows the application to receive WAP push messages."
            imp = "This permission allows the  applications to monitor users messages or delete them without his/her knowledge, this may be used to violate messages availibility and integrity."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_SMS":
            des="This permission Allows the application to read SMS messages."
            imp = "SMS may contain user personal data,this leads to violate data confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.RECEIVE_SMS":
            des="This permission Allows the application to receive SMS messages."
            imp = "SMS may contain user personal data,this leads to violate data confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.SEND_SMS":
            des="This permission Allows the application to send SMS messages."
            imp = "The permission may result in unexpected charges without user confirmation."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.BODY_SENSORS":
            des="This permission Allows the application to access data from sensors that the user uses to measure what is happening inside his/her body, such as heart rate."
            imp = "The permission allows access to users critical and personal health data, which violate user privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_PHONE_NUMBERS":
            des="This permission Allows the application to access to the devices phone numbers."
            imp = "The permission allows access to users critical and personal data, which violate user privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.PROCESS_OUTGOING_CALLS":
            des="This permission Allows the application to see the number being dialed during an outgoing call with the option to redirect the call to a different number or abort the call altogether."
            imp = "The permission may affect the user privacy and the calling service availability."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "com.android.voicemail.permission.ADD_VOICEMAIL":
            des="This permission Allows the application to add voicemails into the system."
            imp = "The permission  may affects voicemail data integrity."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_CALL_LOG":
            des="This permission Allows the application to read the users calls log."
            imp = "The permission may be used to violate the calls log confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.WRITE_CALL_LOG":
            des="This permission Allows the application to write and modify the users calls log."
            imp = "The permission may be used to violate the calls log integrity."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\n description : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.ANSWER_PHONE_CALLS":
            des="This permission Allows the application to answer an incoming phone call."
            imp = "The permission may be used to violate the user privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\n description : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.CALL_PHONE":
            des="This permission Allows the application to initiate a phone call without going through the Dialer user interface for the user to confirm the call."
            imp = "The permission may result in unexpected charges without user confirmation."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_PHONE_STATE":
            des="This permission Allows the application to access the phone state, including the phone number of the device, current cellular network information, the status of any ongoing calls, and a list of any PhoneAccounts registered on the device."
            imp = "The permission may be used to violate the user privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.RECORD_AUDIO":
            des="This permission Allows the application to record audio with the microphone at any time without the user confirmation."
            imp = "The permission may be used to spy on the user and violate their privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.ACCESS_COARSE_LOCATION":
            des="This permission Allows the application to access approximate location."
            imp = "This permission Allows the application to spy on the user and determine their location, this  violate users privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.ACCESS_FINE_LOCATION":
            des="This permission Allows the application to access precise location."
            imp = "This permission Allows the application to spy on users and determine their location, this violate users privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.GET_ACCOUNTS":
            des="This permission Allows the application to get the list of accounts in the Accounts Service include accounts created by other applications installed on the same device."
            imp = "The permission may violate users data confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.WRITE_CONTACTS":
            des="This permission Allows the application to modify the data about user contacts."
            imp = "The permission may be used to violate contacts data integrity."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_CONTACTS":
            des="This permission Allows the application to read the user contacts data including the frequency with which the user have called, emailed, or communicated with them in other ways."
            imp = "The permission allows access to users critical and personal data, which violate user privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.CAMERA":
            des="This permission Allows the application to  take pictures and videos with the device camera."
            imp = "The permission allows the app to use the camera at any time without the user confirmation. This may be used to spy on users and violate their privacy."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.WRITE_CALENDAR":
            des="This permission Allows the application to write or modify the users calendar data."
            imp = " The permission may be used to violate Calendar integrity."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)

        elif value == "android.permission.READ_CALENDAR":
            des="This permission Allows the application to read the users calendar data."
            imp = "The permission may be used to violate Calendar confidentiality."
            recom = "The application must not request this permission unless it is required for the application to function correctly."
            state = 'Warning'
            print "\nparameter : %s\nvalue : Dangerous permission\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,imp,recom,state)  

        else:
            des=" The application asks for a SAFE PERMISSION, this kind of permission is granted automatically and do not violate the user privacy."
            state = 'Good'
            print "\nparameter : %s\nvalue : Safe permission\ndescription %s\nstatus : %s\n"%(usesper.getAttribute("android:name"),des,state)

    #Analysing application's permissions"
    for permission in permissions:
        protectLevel = permission.getAttribute("android:protectionLevel") 
        if (not protectLevel) or (protectLevel == "normal"):
            des="The system will automatically grant this permission to a requesting application at installation, without asking for the user explicit approval."
            imp = "normal protection level permissions may lead to critical data and features sharing if not used carefuly."
            recom = "Define and user custom permissions carefuly. if you want to share data between your own applications, it is recommanded to use Signature protection level permissions."
            state = 'Warning'
            print "\nparameter : %s\nvalue : normal Protection Level\n description : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(permission.getAttribute("android:name"),des,imp,recom,state)
            
        elif protectLevel == "dangerous":
            des="The system will not automatically grant this permission to a requesting application unless the user explicitly confirm it."
            state = 'Good'
            print "\nparameter : %s\nvalue : dangerous Protection Level\ndescription %s\nstatus : %s\n"%(permission.getAttribute("android:name"),des,state)

        elif protectLevel == "signature":
            des="The system will grant this permission only if a requesting application is signed with the same certificate as your application."
            state = 'Good'
            print "\nparameter : %s\nvalue : signature Protection Level\ndescription %s\nstatus : %s\n"%(permission.getAttribute("android:name"),des,state)
        
    #Analysing application's uses-sdks"
    for uses_sdk in uses_sdks:
        minVersion = uses_sdk.getAttribute("android:minSdkVersion")
        maxVersion = uses_sdk.getAttribute("android:maxSdkVersion")
        targetSdkVersion = uses_sdk.getAttribute("android:targetSdkVersion")
        flag = 0
        if not(minVersion):
            flag = 1
            des="minSdkVersion is not declared which indicate that your application is compatible with all android versions."
            imp = "This parameter impact your application disponibility.which means that your application will crush at runtime if not compatible with a given android version."
            recom = "minSdkVersion parameter must be set to a value above 1."
            state = 'ERROR'
            print "\nparameter : minSdkVersion\nvalue : None\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)

        elif minVersion == 1:
            des="minSdkVersion is set to 1 which indicate that your application is compatible with all android versions."
            imp = "This parameter impact your application disponibility.which means that your application will crush at runtime if not compatible with a given android version"
            recom = "minSdkVersion parameter must be set to a value above 1."
            state = 'ERROR'
            print "\nparameter : minSdkVersion\nvalue : 1\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)

        if maxVersion:
            flag = 1
            des="The application is only compatible with systems with API Level below or equal to %d"%(maxVersion)
            imp = "This parameter impact your application disponibility.If the API Level used by the system is higher than the maxSdkVersion, the system will prevent the installation of the application furthermore it will result in your application being removed from users devices after a system update to a higher API Level."
            recom = "Declaring maxSdkVersion attribute is not recommended and should be keeped void."
            state = 'ERROR'
            print "\nparameter : maxSdkVersion\nvalue : %s\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(maxVersion,des,imp,recom,state)
    
    #Analysing application's services"
    for service in services:
        if service.getAttribute("android:permission"):
            des="the service is protected with a specific permission, this way the service data are only shared with legitime applications."
            state = 'Good'
            print "\nparameter : %s\nvalue : Service\ndescription %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,state)

        elif not(service.getAttribute("android:exported")):
            ifilter = False
            sp = False
            for node in service.childNodes:
                if node.nodeName == 'intent-filter':
                    ifilter = True
            if service.getAttribute("android:permission") or application_permission:
                sp = True
            if ifilter and (not(sp)):
                des="the service is exported but not protected by any specific permission."
                imp = "Exporting services without any permission may lead to critical features sharing with other application."
                recom ="It is recommanded to define a permission when exporting a service using android:permission parameter, this way you limit the acces to applications services."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Service\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,imp,recom,state)

            elif not(ifilter):
                des="the service is not exported with external applications, which means that its data is internal to the application"
                state = 'Good'
                print "\nparameter : %s\nvalue : Service\ndescription %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,state)

            elif ifilter and sp:
                des="the service is exported but only with applications which have specific permission. this way service data are only shared with legitime applications"
                state = 'Good'
                print "\nparameter : %s\nvalue : Service\ndescription %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,state)

        elif service.getAttribute("android:exported") == 'true':
            if not(service.getAttribute("android:permission") or application_permission):
                des="the service is exported but not protected by any specific permission."
                imp = "Exporting services without any permission may lead to critical features sharing with other application."
                recom ="It is recommanded to define a permission when exporting a service using android:permission parameter, this way you limit the acces to applications services."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Service\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,imp,recom,state)

            else:
                des="the service is exported but only with applications which have specific permission. this way service data are only shared with legitime applications."
                state = 'Good'
                print "\nparameter : %s\nvalue : Service\ndescription %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,state)

        else:
            des="the service is not exported with external applications, which means that its data is internal to the application."
            state = 'Good'
            print "\nparameter : %s\nvalue : Service\ndescription %s\nstatus : %s\n"%(service.getAttribute("android:name"),des,state)
    
    #Analysing application's receivers"
    for receiver in receivers:
        if receiver.getAttribute("android:permission"):
            des="the Broadcast receiver is protected with a specific permission, this way the receiver data are only shared with legitime applications."
            state = 'Good'
            print "\nparameter : %s\nvalue : Broadcast receiver\ndescription %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,state)

        elif not(receiver.getAttribute("android:exported")):
            ifilter = False
            sp = False
            for node in receiver.childNodes:
                if node.nodeName == 'intent-filter':
                    ifilter = True
            if receiver.getAttribute("android:permission") or application_permission:
                sp = True
            if ifilter and (not(sp)):
                des="the Broadcast receiver is exported but not protected by any specific permission."
                imp = "Exporting Broadcast receivers without any permission may allow  malicious or unautorized applications to receive critical broadcast data."
                recom ="It is recommanded to define a permission when exporting a Broadcast receivers using android:permission parameter, this way you limit the acces to applications Broadcast receivers."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Broadcast receiver\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,imp,recom,state)

            elif not(ifilter):
                des="the Broadcast receiver is not exported with external applications, which means that its data is internal to the application"
                state = 'Good'
                print "\nparameter : %s\nvalue : Broadcast receiver\ndescription %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,state)

            elif ifilter and sp:
                des="the Broadcast receiver is exported but only with applications which have specific permission. this way receiver data are only shared with legitime applications"
                state = 'Good'
                print "\nparameter : %s\nvalue : Broadcast receiver\ndescription %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,state)

        elif receiver.getAttribute("android:exported") == 'true':
            if not(receiver.getAttribute("android:permission") or application_permission):
                des="the Broadcast receiver is exported but not protected by any specific permission."
                imp = "Exporting Broadcast receivers without any permission may allow  malicious or unautorized applications to receive critical broadcast data."
                recom ="It is recommanded to define a permission when exporting a Broadcast receivers using android:permission parameter, this way you limit the acces to applications Broadcast receivers."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Broadcast receiver\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,imp,recom,state)

            else:
                des="the receiver is exported but only with applications which have specific permission. this way receiver data are only shared with legitime applications"
                state = 'Good'
                print "\nparameter : %s\nvalue : Broadcast receiver\ndescription %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,state)

        else:
            des="the receiver is not exported with external applications, which means that its data is internal to the application"
            state = 'Good'
            print "\nparameter : %s\nvalue : Broadcast receiver\ndescription %s\nstatus : %s\n"%(receiver.getAttribute("android:name"),des,state)
                
    #Analysing application's providers"
    for provider in providers:
        # before API level 17 content providers were exported by default
        tmp_grants =  provider.getElementsByTagName('grant-uri-permission')
        if targetSdkVersion <= 17:
            if provider.getAttribute("android:permission") or provider.getAttribute("android:readpermission") or provider.getAttribute("android:writepermission"):
                des="the Content provider is protected with a specific permission, this way the provider data are only shared with legitime applications"
                state = 'Good'
                print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)

            elif provider.getAttribute("android:exported") == 'false':
                des="the provider is not exported with external applications, which means that its data is internal to the application"
                state = 'Good'
                print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)

            else:
                des="the content provider is shared with other applications without being protected by any specific permission."
                imp ="Exporting Content providers without any permission, allow other applications to read the content providers data, which leads to data confidentiality violation."
                recom = "It is recommanded to define a permission when exporting a content provider using android:permission, android:readpermission or  android:writepermission parameter, this way you limit the acces to applications Content providers."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Provider\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,imp,recom,state)

        elif provider.getAttribute("android:grantUriPermissions") == 'true':
            des="the Content provider is exported temporarily with other applications.this way the content provider data are only shared when truely needed."
            state = 'Good'
            print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)

        elif tmp_grants :
            des="the Content provider only share a subsets of app data temporarily with other applications.this way only a subsets of the content provider data are shared when truely needed."
            state = 'Good'
            print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)
            
        elif provider.getAttribute("android:exported")=='true':
            if not(provider.getAttribute("android:permission") or provider.getAttribute("android:readpermission") or provider.getAttribute("android:writepermission")):
                des="the content provider is shared with other applications without being protected by any specific permission."
                imp ="Exporting Content providers without any permission, allow other applications to read the content providers data, which leads to data confidentiality violation."
                recom = "It is recommanded to define a permission when exporting a content provider using android:permission, android:readpermission or  android:writepermission parameter, this way you limit the acces to applications Content providers."
                state = 'Warning'
                print "\nparameter : %s\nvalue : Provider\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,imp,recom,state)

            else:
                des="the provider is exported but only with applications which have specific permission. this way the content provider data are only shared with legitime applications"
                state = 'Good'
                print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)

        else:
            des="the provider is not exported with external applications, which means that its data is internal to the application"
            state = 'Good'
            print "\nparameter : %s\nvalue : Content provider\ndescription %s\nstatus : %s\n"%(provider.getAttribute("android:name"),des,state)
    
    #Analysing application's meta-data"
    boolean=0
    for meta_data in meta_datas:
        if any(x in meta_data.getAttribute("android:name") for x in keywords):
            boolean = 1
            if meta_data.getAttribute("android:name").lower() == "com.google.android.geo.api_key":
                apikey = meta_data.getAttribute("android:value")
                response = requests.post(url="https://www.googleapis.com/geolocation/v1/geolocate?key=%s"%apikey,params={'Content-Type':'application/json'})
                response_code = response.status_code
                if response_code == 200:
                    des="you account Google geo services is accessible using your apikey found in AndroidManifest."
                    imp ="Hardcoded Apikeys may be used to abuse the developpers service account, by either consuming credit for paying services or making the serivce unavailable."
                    recom ="Apply SDK restriction on for your Google geo services account."
                    state = 'ERROR'
                    print "\nparameter : %s\nvalue : %s\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(meta_data.getAttribute("android:name"),meta_data.getAttribute("android:value"),des,imp,recom,state)
                    
                if response_code == 403:
                    des="Access to your Google geo services account is restricted"
                    state = 'Good'
                    print "\nparameter : Hardcoded ApiKeys\nvalue : None\ndescription %s\nstatus : %s\n"%(des,state)
            else:  
                des="Hardcoded ApiKey found in AndroidManifest file."
                imp ="Hardcoded Apikeys may be used to abuse the developpers service account, by either consuming credit for paying services or making the serivce unavailable."
                recom ="It is recommended to store Apikeys at a remote endpoint and get them on runtime or save them in resource files or as building variables in gradle."
                state = 'ERROR'
                print "\nparameter : %s\nvalue : %s\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(meta_data.getAttribute("android:name"),meta_data.getAttribute("android:value"),des,imp,recom,state)

        if (meta_data.getAttribute("android:name") == "android.webkit.WebView.EnableSafeBrowsing") and (meta_data.getAttribute("android:value") == "false"):
            des="Android SafeBrowing is disabled for webview within your application"
            imp ="When disabling SafeBrowsing for webview within your application your application is exposed to a security risk and could load URLs wich may contain malicious content such as Trojans."
            recom ="It is recommended to enable SafeBrowsing for webview in your application. Furthermore you can customize your application response to URLs with known threats using Android SafeBrowsing API."
            state = 'ERROR'
            print "\nparameter : %s\nvalue : %s\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(meta_data.getAttribute("android:name"),meta_data.getAttribute("android:value"),des,imp,recom,state)

    if boolean == 0:    
        des="No hardcoded Apikey found in resources files"
        state = 'Good'
        print "\nparameter : Hardcoded ApiKeys\nvalue : None\ndescription %s\nstatus : %s\n"%(des,state)

    #Analysing Intent-filter for URL Schemes
    boolean = 0
    for intent in intent_filters:
        mimeType = False
        scheme = False
        AppLinks = None
        deepLink = None
        datas = intent.getElementsByTagName("data")
        if targetSdkVersion >=23:
            if intent.getAttribute("android:autoVerify") == "true":
                AppLinks = True
            else:
                AppLinks = False
        else:
            deepLink = True

        for data in datas:
            if data.getAttribute("android:scheme") and data.getAttribute("android:host"):
                scheme = True
            if data.getAttribute("android:mimeType"):
                mimeType = True
        
        if scheme and AppLinks:
            des="App Links assure that the OS launch the URL directly by the application.misconfiguration could be tricky and leads to link hijacking and phishing make sure to implement it properly."
            state = 'Good'
            print "\nparameter : AppLinks\nvalue : Enabled\ndescription : %s\nstatus : %s\n"%(des,state)
            boolean = 1

        elif scheme and not AppLinks:
            des="The application uses URL scheme to open URLs."
            imp = "URL scheme are vulnerable to hijacking and phishing attacks"
            recom = "you must consider implementing App Links, to associate the app component with your website and prventing other apps from opening the URL."
            state = 'Warning'
            print "\nparameter : AppLinks\nvalue : Disabled\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)
            boolean = 1

        elif scheme and deepLink:
            des="The application uses URL scheme to open URLs."
            imp = "URL scheme are vulnerable to hijacking and phishing attacks."
            recom = "you must consider implementing App Links, to associate the app component with your website and prventing other apps from opening the URL. Availble for API Level 23 and above."
            state = 'Warning'
            print "\nparameter : DeepLinks\nvalue : Enabled\ndescription : %s\nimpact : %s\nrecommandation : %s\nstatus : %s\n"%(des,imp,recom,state)
            boolean = 1
            
    if boolean == 0:
        des="No URL scheme are used within the application which decrease hijacking and phishing attacks possibility."
        state = 'Good'
        print "\nparameter : DeepLinks\nvalue : Disabled\ndescription : %s\nstatus : %s\n"%(des,state)


def main():
    source = sys.argv[1]
    manifest_analysis(source)

if __name__ == "__main__":
    main()


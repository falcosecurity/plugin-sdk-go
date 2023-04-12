/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "info.h"
#include "../../plugin_types.h"
#include "../../plugin_api.h"
#include "stdio.h"

const char* get_default_required_api_version()
{
	return PLUGIN_API_VERSION_STR;
}

const char* check_version_compatible(const char* str){
    int str_version_major;
    int str_version_minor;
    int str_version_patch;
    
    int result = sscanf(str,"%" PRIu32 ".%" PRIu32 ".%" PRIu32,&str_version_major
    ,&str_version_minor,&str_version_patch); 

    char buffer [150];
    if (result != 3){
        sprintf(buffer,"Incorrect format.Expected: Semantic Versioning:%s",PLUGIN_API_VERSION_STR);
        return buffer;
    } 

    if(PLUGIN_API_VERSION_MAJOR != str_version_major){
        sprintf(buffer,"Plugin sdk's Major version disagrees. Expected: Major version should be equal to %d but got %d",PLUGIN_API_VERSION_MAJOR,str_version_major);
        return buffer;
    }
    if(PLUGIN_API_VERSION_MINOR < str_version_minor){
        sprintf(buffer,"Plugin sdk's Minor version disagrees. Expected: Minor version should be less than %d but got %d",PLUGIN_API_VERSION_MINOR,str_version_minor);
        return buffer;
    }
    if(PLUGIN_API_VERSION_MAJOR == str_version_major && 
    PLUGIN_API_VERSION_PATCH < str_version_patch){
        sprintf(buffer,"Plugin sdk's Path version disagrees. Expected: Patch version should be less than %d but got %d",PLUGIN_API_VERSION_PATCH,str_version_patch);
        return buffer;
    }
    return "";
}
#!/bin/bash

echo "solr.backup.alfresco.cronExpression=0 0 0 1 1 ? 2200" >> "/opt/alfresco/tomcat/shared/classes/alfresco-global.properties"
echo "solr.backup.archive.cronExpression=0 0 0 1 1 ? 2200" >>  "/opt/alfresco/tomcat/shared/classes/alfresco-global.properties"
echo "solr.secureComms=none" >> "/opt/alfresco/tomcat/shared/classes/alfresco-global.properties"
echo "system.content.orphanProtectDays=1" >>  "/opt/alfresco/tomcat/shared/classes/alfresco-global.properties"

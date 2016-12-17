#!/usr/bin/python
import json
import os
import re
import shutil
import sys
import time
import zipfile

__author__ = 'Sebastien LANGOUREAUX'

ALFRESCO_PATH = '/opt/alfresco'

class ServiceRun():

  def set_database_connection(self, db_type, db_host, db_port, db_name, db_user, db_password):
      global ALFRESCO_PATH

      if db_type not in ["postgresql", "mysql"]:
          raise KeyError("DB type must be Postgresql or Mysql")

      if db_type == "mysql" and (db_host == "localhost" or db_host == "127.0.0.1"):
          raise KeyError("For local database, you must use Postgresql")

      if db_host != "localhost" and db_host != "127.0.0.1":
          self.replace_all('/etc/supervisor/conf.d/supervisord-postgresql.conf', 'autostart\s*=.*', 'autostart=false')
          self.replace_all('/etc/supervisor/conf.d/supervisord-postgresql.conf', 'autorestart\s*=.*', 'autorestart=false')
      else:
          self.replace_all('/etc/supervisor/conf.d/supervisord-postgresql.conf', 'autostart\s*=.*', 'autostart=true')
          self.replace_all('/etc/supervisor/conf.d/supervisord-postgresql.conf', 'autorestart\s*=.*', 'autorestart=true')

      if db_host is None or db_host == "":
          raise KeyError("You must provide db_host")

      if db_port is None or db_port == "":
          raise KeyError("You must provide db_port")

      if db_name is None or db_name == "":
          raise KeyError("You must provide db_name")

      if db_user is None or db_user == "":
          raise KeyError("You must provide db_user")

      if db_password is None or db_password == "":
          raise KeyError("You must provide db_password")

      db_conn_params = ""
      if db_type == "mysql":
          db_conn_params = "?useSSL=false&useUnicode=true&characterEncoding=utf8"
          db_driver = "com.mysql.jdbc.Driver"
      else:
          db_driver = "org.postgresql.Driver"

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'db.driver\s*=.*', 'db.driver=' + db_driver)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'db.username\s*=.*', 'db.username=' + db_user)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'db.password\s*=.*', 'db.password=' + db_password)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'db.name\s*=.*', 'db.name=' + db_name)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'db.url\s*=.*', 'db.url=jdbc:' + db_type + '://' + db_host + ':' + db_port + '/' + db_name + db_conn_params)


  def set_alfresco_context(self, host, port, protocol):
      global ALFRESCO_PATH

      if host is None or host == "":
          raise KeyError("You must provide host")

      if port is None or port == "":
          raise KeyError("You must provide port")

      if protocol is None or protocol == "":
          raise KeyError("You must provide protocol")

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'alfresco.host\s*=.*', 'alfresco.host=' + host)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'alfresco.port\s*=.*', 'alfresco.port=' + port)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'alfresco.protocol\s*=.*', 'alfresco.protocol=' + protocol)



  def set_share_context(self, host, port, protocol):
      global ALFRESCO_PATH

      if host is None or host == "":
          raise KeyError("You must provide host")

      if port is None or port == "":
          raise KeyError("You must provide port")

      if protocol is None or protocol == "":
          raise KeyError("You must provide protocol")

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'share.host\s*=.*', 'share.host=' + host)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'share.port\s*=.*', 'share.port=' + port)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'share.protocol\s*=.*', 'share.protocol=' + protocol)


  def set_ftp(self, enable, port, port_start, port_end):
      global ALFRESCO_PATH

      if port is None or port == "":
          raise KeyError("You must provide port")

      if enable not in ["true", "false"]:
          raise KeyError("Enable must be true or false")

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'ftp.enabled\s*=.*', 'ftp.enabled=' + enable)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'ftp.port\s*=.*', 'ftp.port=' + port)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'ftp.dataPortFrom\s*=.*', 'ftp.dataPortFrom=' + port_start)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'ftp.dataPortTo\s*=.*', 'ftp.dataPortTo=' + port_end)

  def set_core(self, environment):
      global ALFRESCO_PATH

      if environment not in ["UNKNOWN", "TEST", "BACKUP", "PRODUCTION"]:
          raise KeyError("Environment must be UNKNOWN, TEST, BACKUP or PRODUCTION")

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'system.serverMode\s*=.*', 'system.serverMode=' + environment)
      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'alfresco.authentification.allowGuestLogin\s*=.*', 'alfresco.authentification.allowGuestLogin=false')



  def set_mail(self, host, port, user, password, protocol, starttls_enable, mail_sender):
      global ALFRESCO_PATH

      if host is not None and host != "":
          if port is None or port == "":
              raise KeyError("You must provide port")
          if protocol is None or protocol == "":
              raise KeyError("You must provide protocol")
          if mail_sender is None or mail_sender =="":
              raise KeyError("You must provide the mail sender")
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.host\s*=.*', 'mail.host=' + host)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.port\s*=.*', 'mail.port=' + port)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.protocol\s*=.*', 'mail.protocol=' + protocol)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.from.default\s*=.*', 'mail.from.default=' + mail_sender)
      else:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.host\s*=', '#mail.host=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.port\s*=', '#mail.port=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.protocol\s*=', '#mail.protocol=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.from.default\s*=', 'mail.from.default=')

      if user is not None and user != "":
          if password is None or password == "":
              raise KeyError("You must provide password")
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.username\s*=.*', 'mail.username=' + user)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.password\s*=.*', 'mail.password=' + password)

          if protocol == "smtp":
              self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtp.auth\s*=.*', 'mail.smtp.auth=true')
              if starttls_enable == "true":
                  self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtp.starttls.enable\s*=.*', 'mail.smtp.starttls.enable=true')
              else:
                  self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtp.starttls.enable\s*=', '#mail.smtp.starttls.enable=')
          elif protocol == "smtps":
              self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtps.auth\s*=.*', 'mail.smtps.auth=true')
              if starttls_enable == "true":
                  self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtps.starttls.enable\s*=.*', 'mail.smtps.starttls.enable=true')
              else:
                  self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtps.starttls.enable\s*=', '#mail.smtps.starttls.enable=')
      else:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.username\s*=', '#mail.username=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.password\s*=', '#mail.password=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtp.auth\s*=', '#mail.smtp.auth=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtps.auth\s*=', '#mail.smtps.auth=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtp.starttls.enable\s*=', '#mail.smtp.starttls.enable=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.mail.smtps.starttls.enable\s*=', '#mail.smtps.starttls.enable=')



  def set_cifs(self, enable, server_name, domain):
      global ALFRESCO_PATH

      if enable == "true":
          if server_name is None or server_name == "":
              raise KeyError("You must provide the server name")
          if domain is None or domain == "":
              raise KeyError("You must provide the domain")

          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.enabled\s*=.*', 'cifs.enabled=true')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.Server.Name\s*=.*', 'cifs.Server.Name=' + server_name)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.domain\s*=.*', 'cifs.domain=' + domain)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.hostannounce\s*=.*', 'cifs.hostannounce=true')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.broadcast\s*=.*', 'cifs.broadcast=0.0.0.255')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.ipv6.enabled\s*=.*', 'cifs.ipv6.enabled=false')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.alfresco.authentication.authenticateCIFS\s*=.*', 'alfresco.authentication.authenticateCIFS=true')
          
      else:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.enabled\s*=', '#cifs.enabled=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.Server.Name\s*=', '#cifs.Server.Name=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.domain\s*=', '#cifs.domain=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.hostannounce\s*=', '#cifs.hostannounce=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.broadcast\s*=', '#cifs.broadcast=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.cifs.ipv6.enabled\s*=', '#cifs.ipv6.enabled=')

  def set_ldap(self, enable, auth_format, host, user, password, list_admins, search_base_group, search_base_user, group_query, group_differential_query, person_query, person_differential_query):
      global ALFRESCO_PATH

      if enable == "true":
          if auth_format is None or auth_format == "":
              raise KeyError("You must provide auth_format")
          if host is None or host == "":
              raise KeyError("You must provide host")
          if user is None or user == "":
              raise KeyError("You must provide user")
          if password is None or password == "":
              raise KeyError("You must provide password")
          if list_admins is None or list_admins == "":
              raise KeyError("You must provide list admins")
          if search_base_group is None or search_base_group == "":
              raise KeyError("You must provide the search base group")
          if search_base_user is None or search_base_user == "":
              raise KeyError("You must provide the search base user")

          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'authentication.chain\s*=.*', 'authentication.chain=alfrescoNtlm1:alfrescoNtlm,ldap1:ldap')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.authentication.userNameFormat\s*=.*', 'ldap.authentication.userNameFormat=' + auth_format)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.authentication.java.naming.provider.url\s*=.*', 'ldap.authentication.java.naming.provider.url=ldap://' + host + ':389')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.authentication.defaultAdministratorUserNames\s*=.*', 'ldap.authentication.defaultAdministratorUserNames=' + list_admins)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.java.naming.security.principal\s*=.*', 'ldap.synchronization.java.naming.security.principal=' + user)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.java.naming.security.credentials\s*=.*', 'ldap.synchronization.java.naming.security.credentials=' + password)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.groupQuery\s*=.*', 'ldap.synchronization.groupQuery=' + group_query)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.groupDifferentialQuery\s*=.*', 'ldap.synchronization.groupDifferentialQuery=' + group_differential_query)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.personQuery\s*=.*', 'ldap.synchronization.personQuery=' + person_query)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.personDifferentialQuery\s*=.*', 'ldap.synchronization.personDifferentialQuery=' + person_differential_query)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.groupSearchBase\s*=.*', 'ldap.synchronization.groupSearchBase=' + search_base_group)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/extension/subsystems/Authentication/ldap/ldap1/ldap-authentication.properties', 'ldap.synchronization.userSearchBase\s*=.*', 'ldap.synchronization.userSearchBase=' + search_base_user)
      else:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', 'authentication.chain\s*=.*', 'authentication.chain=alfrescoNtlm1:alfrescoNtlm')

  def init_data_folder(self):
      global ALFRESCO_PATH

      if len(os.listdir(ALFRESCO_PATH + '/alf_data')) < 3:
          os.system('mv ' + ALFRESCO_PATH + '/alf_data_org/* ' + ALFRESCO_PATH + '/alf_data/')
          os.system('chown -R alfresco:alfresco ' + ALFRESCO_PATH + '/alf_data')


  def set_reverse_proxy(self, url):
      global ALFRESCO_PATH


      if url is None or url == "":
          raise KeyError("You must provide url")

      csrf_policy = """
<config evaluator="string-compare" condition="CSRFPolicy" replace="true">

      <!--
         Will be used and exposed to the client side code in Alfresco.contants.CSRF_POLICY.
         Use the Alfresco.util.CSRFPolicy.getHeader() or Alfresco.util.CSRFPolicy.getParameter() with Alfresco.util.CSRFPolicy.getToken()
         to set the token in custom 3rd party code.
       -->
      <client>
         <cookie>Alfresco-CSRFToken</cookie>
         <header>Alfresco-CSRFToken</header>
         <parameter>Alfresco-CSRFToken</parameter>
      </client>

      <!-- The first rule with a matching request will get its action invoked, the remaining rules will be ignored. -->
      <filter>
         <!--
            Certain Surf POST requests form the WebScript console must be allowed to pass without a token since
            the Surf WebScript console code can't be dependent on a Share specific filter.
         -->
         <rule>
            <request>
               <method>POST</method>
               <path>^\/page\/caches\/dependency\/clear|^\/page\/index|^\/page\/surfBugStatus|^\/page\/modules\/deploy|^\/page\/modules\/module|^\/page\/api\/javascript\/debugger</path>
            </request>
            <action name="assertReferer">
               <param name="always">false</param>
               <param name="referer">""" + url + """/.*</param>
            </action>
            <action name="assertOrigin">
               <param name="always">false</param>
               <param name="origin">""" + url + """</param>
            </action>
         </rule>

         <!-- Certain Share POST requests does NOT require a token -->
         <rule>
            <request>
               <method>POST</method>
               <path>^/page/dologin.*|^\/page/site\/[^\/]+\/start-workflow|^\/page/start-workflow</path>
            </request>
            <action name="assertReferer">
               <param name="always">false</param>
               <param name="referer">""" + url + """/.*</param>
            </action>
            <action name="assertOrigin">
               <param name="always">false</param>
               <param name="origin">""" + url + """</param>
            </action>
         </rule>

         <!-- Clear the token when logging out -->
         <rule>
            <request>
               <method>GET</method>
               <path>^/page/dologout.*</path>
            </request>
            <action name="clearToken">
               <param name="session">Alfresco-CSRFToken</param>
               <param name="cookie">Alfresco-CSRFToken</param>
            </action>
         </rule>

         <!-- Make sure the first token is generated -->
         <rule>
            <request>
               <session>
                  <attribute name="_alf_USER_ID">.*</attribute>
                  <attribute name="Alfresco-CSRFToken"/>
                  <!-- empty attribute element indicates null -->
               </session>
            </request>
            <action name="generateToken">
               <param name="session">Alfresco-CSRFToken</param>
               <param name="cookie">Alfresco-CSRFToken</param>
            </action>
         </rule>

         <!-- Refresh token on new "page" visit when a user is logged in -->
         <rule>
            <request>
               <method>GET</method>
               <path>^/page/.*</path>
               <session>
                  <attribute name="_alf_USER_ID">.*</attribute>
                  <attribute name="Alfresco-CSRFToken">.*</attribute>
               </session>
            </request>
            <action name="generateToken">
               <param name="session">Alfresco-CSRFToken</param>
               <param name="cookie">Alfresco-CSRFToken</param>
            </action>
         </rule>

         <!-- Verify multipart requests contains the token as a parameter and also correct referer & origin header if available -->
         <rule>
            <request>
               <method>POST</method>
               <header name="Content-Type">^multipart/.*</header>
               <session>
                  <attribute name="_alf_USER_ID">.*</attribute>
               </session>
            </request>
            <action name="assertToken">
               <param name="session">Alfresco-CSRFToken</param>
               <param name="parameter">Alfresco-CSRFToken</param>
            </action>
            <action name="assertReferer">
               <param name="always">false</param>
               <param name="referer">""" + url + """/.*</param>
            </action>
            <action name="assertOrigin">
               <param name="always">false</param>
               <param name="origin">""" + url + """</param>
            </action>
         </rule>

         <!--
            Verify there is a token in the header for remaining state changing requests and also correct
            referer & origin headers if available. We "catch" all content types since just setting it to
            "application/json.*" since a webscript that doesn't require a json request body otherwise would be
            successfully executed using i.e. "text/plain".
         -->
         <rule>
            <request>
               <method>POST|PUT|DELETE</method>
               <session>
                  <attribute name="_alf_USER_ID">.*</attribute>
               </session>
            </request>
            <action name="assertToken">
               <param name="session">Alfresco-CSRFToken</param>
               <param name="header">Alfresco-CSRFToken</param>
            </action>
            <action name="assertReferer">
               <param name="always">false</param>
               <param name="referer">""" + url + """/.*</param>
            </action>
            <action name="assertOrigin">
               <param name="always">false</param>
               <param name="origin">""" + url + """</param>
            </action>

         </rule>
      </filter>
   </config>
      """

      self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml', '<\/alfresco-config>', csrf_policy + "\n</alfresco-config>")



  def set_vti_setting(self, host, port):

      if host is not None and host != "" and port is not None and port > 0:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.port\s*=.*', 'vti.server.port=7070')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.external.host\s*=.*', 'vti.server.external.host=' + host)
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.external.port\s*=.*', 'vti.server.external.port=' + port)

      else:
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.port\s*=.*', '#vti.server.port=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.external.host\s*=.*', '#vti.server.external.host=')
          self.replace_all(ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties', '^#.vti.server.external.port\s*=.*', '#vti.server.external.port=')


  def disable_log_rotation(self):

      valve_setting = 'prefix="localhost_access_log" suffix=".log" pattern="combined" rotatable="false"'
      self.replace_all(ALFRESCO_PATH + '/tomcat/conf/server.xml', 'prefix="localhost_access_log" suffix=".txt"', valve_setting)
      self.replace_all(ALFRESCO_PATH + '/tomcat/conf/server.xml', re.escape('pattern="%h %l %u %t &quot;%r&quot; %s %b"'), '')

      logging_setting = """
1catalina.org.apache.juli.FileHandler.rotatable = false
2localhost.org.apache.juli.FileHandler.rotatable = false
3manager.org.apache.juli.FileHandler.rotatable = false
4host-manager.org.apache.juli.FileHandler.rotatable = false

1catalina.org.apache.juli.FileHandler.suffix = log
2localhost.org.apache.juli.FileHandler.suffix = log
3manager.org.apache.juli.FileHandler.suffix = log
4host-manager.org.apache.juli.FileHandler.suffix = log
      """

      self.add_end_file(ALFRESCO_PATH + '/tomcat/conf/logging.properties', logging_setting)

  def replace_all(self, file, searchRegex, replaceExp, is_create = True):
    """ Replace String in file with regex
    :param file: The file name where you should to modify the string
    :param searchRegex: The pattern witch must match to replace the string
    :param replaceExp: The string replacement
    :return:
    """

    is_found = False
    regex = re.compile(searchRegex, re.IGNORECASE)

    f = open(file,'r')
    out = f.readlines()
    f.close()

    f = open(file,'w')

    for line in out:
      if regex.search(line) is not None:
        line = regex.sub(replaceExp, line)
        is_found = True

      f.write(line)

    f.close()

    if is_create is True and is_found is False:
        self.add_end_file(file, replaceExp)
        
  def apply_logo(self, light_logo, dark_logo):
    global ALFRESCO_PATH
    
    for theme_name in os.listdir(ALFRESCO_PATH+"/tomcat/webapps/share/themes"):
      if not theme_name.startswith('.'):
        if "Black" in theme_name:
          shutil.copy2(dark_logo,ALFRESCO_PATH+"/tomcat/webapps/share/themes/"+theme_name+"/images/logo.png")
        else:
          shutil.copy2(light_logo,ALFRESCO_PATH+"/tomcat/webapps/share/themes/"+theme_name+"/images/logo.png")

  def add_end_file(self, file, line):
    """ Add line at the end of file
    :param file: The file where you should to add line to the end
    :param line: The line to add in file
    :return:
    """
    with open(file, "a") as myFile:
        myFile.write("\n" + line + "\n")

  def apply_modules(self):
    global ALFRESCO_PATH
    os.system(ALFRESCO_PATH+"/java/bin/java -jar "+ALFRESCO_PATH+"/bin/alfresco-mmt.jar install "+ALFRESCO_PATH+"/amps "+ALFRESCO_PATH+"/tomcat/webapps/alfresco.war -directory $*")
    os.system(ALFRESCO_PATH+"/java/bin/java -jar "+ALFRESCO_PATH+"/bin/alfresco-mmt.jar install "+ALFRESCO_PATH+"/amps_share "+ALFRESCO_PATH+"/tomcat/webapps/share.war -directory $*")
    if os.path.isdir(ALFRESCO_PATH+"/tomcat/webapps/alfresco"):
      shutil.rmtree(ALFRESCO_PATH+"/tomcat/webapps/alfresco")
    if os.path.isdir(ALFRESCO_PATH+"/tomcat/webapps/share"):
      shutil.rmtree(ALFRESCO_PATH+"/tomcat/webapps/share")
    z = zipfile.ZipFile('/opt/alfresco/tomcat/webapps/alfresco.war')
    z.extractall('/opt/alfresco/tomcat/webapps/alfresco')

    z = zipfile.ZipFile('/opt/alfresco/tomcat/webapps/share.war')
    z.extractall('/opt/alfresco/tomcat/webapps/share')

if __name__ == '__main__':

    serviceRun = ServiceRun()

    # We init alfresco config
    os.system('cp ' + ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties.org ' + ALFRESCO_PATH + '/tomcat/shared/classes/alfresco-global.properties')

    # We init share-config
    os.system('cp ' + ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml.org ' + ALFRESCO_PATH + '/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml')

    # We init tomcat setting
    os.system('cp ' + ALFRESCO_PATH + '/tomcat/conf/server.xml.org ' + ALFRESCO_PATH + '/tomcat/conf/server.xml')
    os.system('cp ' + ALFRESCO_PATH + '/tomcat/conf/logging.properties.org ' + ALFRESCO_PATH + '/tomcat/conf/logging.properties')

    # We init data folder
    serviceRun.init_data_folder()

    # We remove log rotation to manage them with logrotate
    serviceRun.disable_log_rotation()

    # We set database
    # We check if official Postgresql container is linked as DB
    if os.getenv('DB_ENV_POSTGRES_DB') is not None:
        serviceRun.set_database_connection('postgresql', 'db', '5432', os.getenv('DB_ENV_POSTGRES_DB'), os.getenv('DB_ENV_POSTGRES_USER'), os.getenv('DB_ENV_POSTGRES_PASSWORD'))
    elif os.getenv('DB_ENV_MYSQL_DATABASE') is not None:
        serviceRun.set_database_connection('mysql', 'db', '3306', os.getenv('DB_ENV_MYSQL_DATABASE'), os.getenv('DB_ENV_MYSQL_USER'), os.getenv('DB_ENV_MYSQL_PASSWORD'))
    else:
        serviceRun.set_database_connection(os.getenv('DATABASE_TYPE', 'postgresql'), os.getenv('DATABASE_HOST', 'localhost'), os.getenv('DATABASE_PORT', '5432'), os.getenv('DATABASE_NAME', 'alfresco'), os.getenv('DATABASE_USER', 'alfresco'), os.getenv('DATABASE_PASSWORD', 'admin'))

    # We set alfresco url
    serviceRun.set_alfresco_context(os.getenv('ALFRESCO_HOSTNAME', '127.0.0.1'), os.getenv('ALFRESCO_PORT', '8080'), os.getenv('ALFRESCO_PROTOCOL', 'http'))

    # We set share url
    serviceRun.set_share_context(os.getenv('SHARE_HOSTNAME', '127.0.0.1'), os.getenv('SHARE_PORT', '8080'), os.getenv('SHARE_PROTOCOL', 'http'))

    # We set ftp
    serviceRun.set_ftp(os.getenv('FTP_ENABLED', 'true'), os.getenv('FTP_PORT', '21'), os.getenv('FTP_PORT_FROM', 1024), os.getenv('FTP_PORT_TO',1099))

    # We set environment
    serviceRun.set_core(os.getenv('ENVIRONMENT', 'PRODUCTION'))

    # We set mail
    serviceRun.set_mail(os.getenv('MAIL_HOST', 'localhost'), os.getenv('MAIL_PORT', '25'), os.getenv('MAIL_USER'), os.getenv('MAIL_PASSWORD'), os.getenv('MAIL_PROTOCOL', 'smtp'), os.getenv('MAIL_STARTTLS_ENABLE', 'false'), os.getenv('MAIL_SENDER', 'alfresco@alfresco.org'))

    # We set CIFS
    serviceRun.set_cifs(os.getenv('CIFS_ENABLED', 'true'), os.getenv('CIFS_SERVER_NAME', 'localhost'), os.getenv('CIFS_DOMAIN', 'WORKGROUP'))

    # We set LDAP
    serviceRun.set_ldap(os.getenv('LDAP_ENABLED', 'false'), os.getenv('LDAP_AUTH_FORMAT'), os.getenv('LDAP_HOST'), os.getenv('LDAP_USER'), os.getenv('LDAP_PASSWORD'), os.getenv('LDAP_ADMINS'), os.getenv('LDAP_GROUP_SEARCHBASE'), os.getenv('LDAP_USER_SEARCHBASE'), os.getenv('LDAP_GROUP_QUERY','(objectClass\=posixGroup)'), os.getenv('LDAP_DIFFERENTIAL_GROUP_QUERY','(&(objectClass\=posixGroup)(!(modifyTimeStamp\<\={0})))'),os.getenv('LDAP_PERSON_QUERY','(objectClass\=inetOrgPerson)'), os.getenv('LDAP_DIFFERENTIAL_PERSON_QUERY','(&(objectClass\=inetOrgPerson)(!(modifyTimeStamp\<\={0})))'))

    # Reverse Proxy
    if os.getenv('REVERSE_PROXY_URL') is not None:
        serviceRun.set_reverse_proxy(os.getenv('REVERSE_PROXY_URL'))

    # We set vti
    serviceRun.set_vti_setting(os.getenv('VTI_HOST'), os.getenv('VTI_PORT'))
    
    # Rebuild war with user amps
    serviceRun.apply_modules()
    
    # Apply logo for all themes
    serviceRun.apply_logo('/etc/light_logo.png','/etc/dark_logo.png')

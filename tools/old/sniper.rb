#
# $Id$

require 'nessus/nessus-xmlrpc'
require 'rex/parser/nessus_xml'

module Msf

class Plugin::Sniper < Msf::Plugin


  class ConsoleCommandDispatcher
   	include Msf::Ui::Console::CommandDispatcher

 	def name
 		"Sniper"
 	end

 	def commands
                                {
					"sniper" => "A sniper test command added by sniper plugin",
					"sniper_help" => "Get help on all commands.",         
                               		"sniper_scan_status" => "Check the status of running scans on your Nessus Server.",
					"sniper_report_list" => "Testing report list"
				}
 	end

	def cmd_sniper(*args)
		print_line("You passed: #{args.join(' ')}")
	end


 	def cmd_sniper_help(*args)
                                tbl = Rex::Ui::Text::Table.new(
                                        'Columns' => [
                                                'Command',
                                                'Help Text'
                                        ]
                                )
                                tbl << [ "Generic Sniper Commands", "" ]
                                tbl << [ "-----------------", "-----------------"]
                                tbl << [ "sniper_help", "Listing of available Sniper commands"]
                                tbl << [ "sniper_scan_status", "List the number of active nessus scans"]
                                print_status ""
                                print_line tbl.to_s
                                print_status ""
 	end


        def sniper_verify_token
                                if @token.nil? or @token == ''
                                        ncusage
                                        return false
                                end
                                true
        end


	def ncusage
                                print_status("%redYou must do this before any other commands.%clr")
                                print_status("Usage: ")
                                print_status("       nessus_connect username:password@hostname:port <ssl ok>")
                                print_status(" Example:> nessus_connect msf:msf@192.168.1.10:8834 ok")
                                print_status("          OR")
                                print_status("       nessus_connect username@hostname:port <ssl ok>")
                                print_status(" Example:> nessus_connect msf@192.168.1.10:8834 ok")
                                print_status("          OR")
                                print_status("       nessus_connect hostname:port <ssl ok>")
                                print_status(" Example:> nessus_connect 192.168.1.10:8834 ok")
                                print_status("          OR")
                                print_status("       nessus_connect")
                                print_status(" Example:> nessus_connect")
                                print_status("This only works after you have saved creds with nessus_save")
                                return
        end


 	def cmd_sniper_scan_status(*args)

     	if args[0] == "-h"
        print_status("Usage: ")
        print_status("       sniper_scan_status")
        print_status(" Example:> sniper_scan_status")
        print_status()
        print_status("Returns scan status items for the server..")
        return
     	end
     #Auth
    	if ! sniper_verify_token
    	return
    	end

     #Check if we are an admin
     	#if ! @n.is_admin
     	#print_status("You need to be an admin for this.")
     	#return
     	#end

     	tbl = Rex::Ui::Text::Table.new(
     	'Columns' => [
     	'Running Scans',
     	])

    #Count how many running scans
    	list=@n.scan_list_uids
    	scans = list.length
    	tbl << [scans]
    	print_good "\n"
    	print_line tbl.to_s
  	end

                    def cmd_sniper_report_list(*args)

                                if args[0] == "-h"
                                        print_status("Usage: ")
                                        print_status("       sniper_report_list")
                                        print_status(" Example:> sniper_report_list")
                                        print_status()
                                        print_status("Generates a list of all reports visable to your user.")
                                        return
                                end

                                if ! sniper_verify_token
                                        return
                                end

                                list=@n.report_list_hash

                                tbl = Rex::Ui::Text::Table.new(
                                        'Columns' => [
                                                'ID',
                                                'Name',
                                                'Status',
                                                'Date'
                                        ])

                                list.each {|report|
                                        t = Time.at(report['timestamp'].to_i)
                                        tbl << [ report['id'], report['name'], report['status'], t.strftime("%H:%M %b %d %Y") ]
                                }
                                print_good("Nessus Report List")
                                print_good "\n"
                                print_line tbl.to_s + "\n"
                                print_status("You can:")
                                print_status("        Get a list of hosts from the report:          nessus_report_hosts <report id>")
                        end



  end

 def initialize(framework, opts)
                super
                add_console_dispatcher(ConsoleCommandDispatcher)
                print_status("Sniper plugin loaded.")
 end


 def cleanup
                remove_console_dispatcher('Sniper')
 end



 def cmd_sniper_scan_status(*args)

     if args[0] == "-h"
	print_status("Usage: ")
	print_status("       sniper_scan_status")
	print_status(" Example:> sniper_scan_status")
	print_status()
	print_status("Returns scan status items for the server..")
	return
     end
     #Auth
     if ! sniper_verify_token_
	return
     end

     #Check if we are an admin
       if ! @n.is_admin
	print_status("You need to be an admin for this.")
	return
       end

     tbl = Rex::Ui::Text::Table.new(
     'Columns' => [
     'Running Scans',
     ])
  
    #Count how many running scans
    list=@n.scan_list_uids
    scans = list.length

    tbl << [scans]
    print_good "\n"
    print_line tbl.to_s
  end


 def name
   "sniper"
 end


 def desc
   "Sniper Bridge for Nessus/Metasploit #{@nbver}"
 end


protected
end

end


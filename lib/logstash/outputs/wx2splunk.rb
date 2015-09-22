# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "date"
require 'json'
require 'time'

# Send events to a splunk instance.
class LogStash::Outputs::Wx2splunk < LogStash::Outputs::Base
  config_name "wx2splunk"
  milestone 1

  # syslog server address to connect to
  #config :host, :validate => :string, :required => true
  
  # syslog server port to connect to
  #config :port, :validate => :number, :required => true

  # syslog server protocol. you can choose between udp and tcp
  #config :protocol, :validate => ["tcp", "udp"], :default => "udp"

  # source host
  config :sourcehost, :validate => :string, :default => "%{host}"

  # application name
  config :appname, :validate => :string, :default => "WX2"

  # splunk target overrides
  config :splunk_targets, :validate => :hash, :default => {}

  public
  def register
      @sockets = {}
  end

  private
  def connect(host, port, protocol)
    @sockets[host] = {} unless @sockets[host]

    if protocol == "udp"
        @sockets[host][port] = UDPSocket.new
        @sockets[host][port].connect(host, port.to_i)
    else
        @sockets[host][port] = TCPSocket.new(host, port.to_i)
    end

  end

  private
  def send(host, port, protocol, message)
        connect(host, port, protocol) unless @sockets[host] && @sockets[host][port]
        @sockets[host][port].write(message + "\r\n")
  end

  private
  def sendToFile(filename, message)
        begin
          file = File.open(filename, "a")
          file.write(message + "\n") 
        rescue IOError => e
          @logger.error("Problem writing to file " + filename)
        ensure
          file.close unless file == nil
        end
  end

  public
  def receive(event)
    host = nil
    port = nil
    protocol = nil

    begin
        return unless output?(event)

        appname = event.sprintf(@appname)
        sourcehost = event.sprintf(@sourcehost)

        fields = event["@fields"]

        metric = event["@message"]
        if metric.index("SPLUNK_METRIC:") == 0
          metric = event["@message"].gsub("SPLUNK_METRIC: ", "")
          if metric.index("{") != 0
            metric = "{}"
            fields["SM"] = JSON.parse(metric)
            fields["timestamp"] = Time.at(Time.now)
          else
            fields["SM"] = JSON.parse(metric)
            time =  fields["SM"]["time"]
            if !time.nil?
              time = Integer(time) rescue time = nil
              if time.nil?
                fields["timestamp"] = fields["SM"]["time"]
              else
                if time > 0x7FFFFFFF
                  time = time/1000
                end
                fields["timestamp"] = Time.at(time)
              end
            else
              fields["timestamp"] = Time.at(Time.now)
            end
          end
          env = fields["SM"]["env"]
          unless env.nil?
              if 'TEST' == env
                  return
              end
          end 
        elsif metric.index("SPLUNK_METRIC_CLIENT:") == 0
          metric = event["@message"].gsub("SPLUNK_METRIC_CLIENT: ", "")
          if metric.index("{") != 0
            metric = "{}"
            fields["SM_C"] = JSON.parse(metric)
            fields["timestamp"] = Time.at(Time.now)
          else
            fields["SM_C"] = JSON.parse(metric)
            time =  fields["SM_C"]["time"]
            if !time.nil?
              time = Integer(time) rescue time = nil
              if time.nil?
                fields["timestamp"] = fields["SM_C"]["time"]
              else
                if time > 0x7FFFFFFF
                  time = time/1000
                end
                fields["timestamp"] = Time.at(time)
              end
            else
              fields["timestamp"] = Time.at(Time.now)
            end
          end
          env = fields["SM_C"]["env"]
          unless env.nil?
              if 'TEST' == env
                  return
              end
          end
          valueField = fields["SM_C"]["value"]
          unless valueField.nil?
            if valueField.is_a?(Hash)
              if valueField.has_key?("screenTimeToDecrypt")
                if valueField["screenTimeToDecrypt"].nil?
                  return
                end
                screenTime = valueField["screenTimeToDecrypt"].to_s
                if 'null' == screenTime
                  return
                end
                if '' == screenTime
                  return
                end
                if '0' == screenTime
                  return
                end
              end
            end
          end
          key = fields["SM_C"]["key"]
          unless key.nil?
            if 'keyRequest' == key
              return
            end
          end
        else
          fields["timestamp"] = Time.at(Time.now)
          metric = "{}"
          fields["SM"] = JSON.parse(metric)
        end

        fields.delete("caller_class_name")
        fields.delete("caller_file_name")
        fields.delete("caller_line_number")
        fields.delete("caller_method_name")
        fields.delete("logger_name")
        fields.delete("thread_name")

        fields["appname"] = appname
        fields["sourcehost"] = sourcehost
        fields["sourceTag"] = "squared" unless fields["sourceTag"]
        
        fields["timeRcvd"] = Time.now.utc.iso8601(3)

        message = event["@fields"].to_json

        @splunk_targets.each do |key, target|
          checkField = target["checkField"]
          checkValue = Regexp.new target["checkValue"]
          value = fields[checkField]
          if checkValue.match value
            host = target["host"]
            port = target["port"]
            protocol = target["protocol"]
            send(host, port, protocol, message)
            filename = "/var/log/logstash/" + event["@environment"] + "-" + fields["sourceTag"] + "-" + appname + ".dump"
            sendToFile(filename, message)
            @logger.info("Sent Splunk event to "+protocol+":"+host+":"+port+" for "+appname)
          end
        end
    rescue => e
        @logger.warn("output exception", :host => host, :port => port,
                 :exception => e, :backtrace => e.backtrace)
        @sockets[host][port].close rescue nil
        @sockets[host][port] = nil
    end
  end

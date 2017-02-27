# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require "logstash/timestamp"
require "logstash/filters/cipher"
require "logstash/filters/xor"
require "logstash/filters/aes"
require 'thread'


class LogStash::Filters::Decrypt < LogStash::Filters::Base

  # The field to perform filter
  #
  # Example, to use the @message field (default) :
  # [source,ruby]
  #     filter { decrypt { source => "message" } }

  #Config_name for the Logstash Config
  config_name "decrypt"

  # Replace the message with this value.
  config :source, :validate => :string, :required => true


  public
  def register
    # Add instance variables
    @campaigns = Dir.glob("campaigns/*.json")
  end # def register

  public
  def filter(event)

    if @source
      source = event.get(@source)
      # Replace the event message with our message as configured in the
      # config file.
      parsed = LogStash::Json.load(source)

      parsed_timestamp = parsed.delete(LogStash::Event::TIMESTAMP)
      begin
        timestamp = parsed_timestamp ? LogStash::Timestamp.coerce(parsed_timestamp) : nil
      rescue LogStash::TimestampParserError => e
        timestamp = nil
      end

      threads = []

      @campaigns.each do |file|
        file = File.read(file)
        campaign = LogStash::Json.load(file)
        @keywordstrategy = nil
        @strategies = campaign['SearchStrategies']
        @strategies.each do |strategy|
          if strategy["type"].eql? "KeywordStrategy"
            @logger.info("Found Keyword Strategy")
            @keywordstrategy = strategy
          end
        end
        if parsed["body"].nil? || parsed["body"].empty?
          @logger.info("Empty Body -> Skip")
        elsif @keywordstrategy.nil?
          @logger.info("No Keyword Strategy found -> Skip")
        elsif parsed["body"].include? @keywordstrategy["prefix"]
          @logger.info("Decrypt Body")
          threads << Thread.new {

             if campaign["encryption"]["xor"].any?
               xor=Xor.new(@keywordstrategy["prefix"],parsed["body"],campaign["encryption"]["xor"],@keywordstrategy["keywords"])
               result = xor.xordecrypt
               if result[0]
                 parsed["decrypted"] = result[1]
                 parsed["tags"] = [campaign["name"],"XOR"]
               end
             end

             if campaign["encryption"]["aes"].any?
               aes=Aes.new(@keywordstrategy["prefix"],parsed["body"],campaign["encryption"]["aes"],@keywordstrategy["keywords"])
               result = aes.aesdecrypt
               if result[0]
                 parsed["decrypted"] = result[1]
                 parsed["tags"] = [campaign["name"],"AES"]
               end
             end
            }
        else
          @logger.info("Prefix not in Payload -> Skip")
        end
      end

      threads.each { |thr| thr.join }

      # using the event.set API
      parsed.each{|k, v| event.set(k, v)}

      if parsed_timestamp
        if timestamp
          event.timestamp = timestamp
        else
          event.timestamp = LogStash::Timestamp.new
          @logger.warn("Unrecognized #{LogStash::Event::TIMESTAMP} value, setting current time to #{LogStash::Event::TIMESTAMP}, original in #{LogStash::Event::TIMESTAMP_FAILURE_FIELD} field", :value => parsed_timestamp.inspect)
          event.tag(LogStash::Event::TIMESTAMP_FAILURE_TAG)
          event.set(LogStash::Event::TIMESTAMP_FAILURE_FIELD, parsed_timestamp.to_s)
        end
      end
      # correct debugging log statement for reference
      # using the event.get API
      @logger.info("Event after filter", :event => event)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example

#!/usr/bin/env ruby
# frozen_string_literal: true

# End-to-end smoke test against Telegram's real production DCs.
#
# Required env vars:
#   TG_API_ID   — your api_id from my.telegram.org
#   TG_API_HASH — your api_hash from my.telegram.org
#   TG_PHONE    — phone number in international format, e.g. +5215512345678
#
# Optional:
#   TG_CHAT     — chat_id to fetch history from. If omitted, only prints
#                 a few dialogs.
#   TG_SESSION  — path for the session file. Default: /tmp/tg_smoke.session
#
# Run twice. The first run prompts for the SMS/Telegram code; the second
# run should skip the prompt entirely, proving session persistence works.

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "tg_client"
require "logger"

logger = Logger.new($stderr, level: ENV["DEBUG"] ? :debug : :info)
session_file = ENV.fetch("TG_SESSION", "/tmp/tg_smoke.session")

client = TgClient::Client.new(
  Integer(ENV.fetch("TG_API_ID")),
  ENV.fetch("TG_API_HASH"),
  session_file: session_file,
  logger:       logger
)

phase = client.authenticate(phone: ENV.fetch("TG_PHONE"))
puts "auth: #{phase}"

dialogs = client.get_dialogs(limit: 10)
puts "dialogs: #{Array(dialogs[:dialogs]).size}"
Array(dialogs[:chats]).first(3).each do |chat|
  puts "  chat #{chat[:id]} (#{chat[:_]}) #{chat[:title]}"
end

chat_id = ENV["TG_CHAT"]
if chat_id
  messages = client.get_history(
    chat_id:   Integer(chat_id),
    date_from: Date.today + 1,
    limit:     10
  )
  puts "history: #{messages.size} messages"
  messages.first(5).each do |m|
    text = m[:text].to_s.lines.first.to_s.chomp[0, 80]
    puts "  #{m[:date].iso8601}  #{m[:from_name] || m[:from_id]}: #{text}"
  end
end

require 'rex'
require 'rex/proto/http'

class HttpServer < Rex::Proto::Http::Server
  def dispatch_request(cli, request)
    resp = Rex::Proto::Http::Response.new

    resp.body = "Test"
    cli.send_response(resp)
  end
end

if __FILE__ == $0
  test = HttpServer.new(8081)
  test.start
  test.wait
end

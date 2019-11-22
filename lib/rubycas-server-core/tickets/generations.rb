require 'rubycas-server-core/util'

module RubyCAS
  module Server
    module Core
      module Tickets
        module Generations
          # One time login ticket for given client
          def generate_login_ticket(client)
            lt = LoginTicket.new
            lt.ticket = "LT-" + Util.random_string
            lt.client_hostname = client
            if lt.save!
              $LOG.debug("Login ticket '#{lt.ticket} has been created for '#{lt.client_hostname}'")
              return lt
            else
              return nil
            end
          end

          # Creates a TicketGrantingTicket for the given username. This is done when the user logs in
          # for the first time to establish their SSO session (after their credentials have been validated).
          #
          # The optional 'extra_attributes' parameter takes a hash of additional attributes
          # that will be sent along with the username in the CAS response to subsequent
          # validation requests from clients.
          def generate_ticket_granting_ticket(
            username,
            client,
            remember_me = false,
            extra_attributes = {}
          )
            tgt = TicketGrantingTicket.new
            tgt.ticket = "TGC-" + Util.random_string
            tgt.username = username
            tgt.remember_me = remember_me
            tgt.extra_attributes = extra_attributes.to_s
            tgt.client_hostname = client
            if tgt.save!
              $LOG.debug("Generated ticket granting ticket '#{tgt.ticket}' for user" +
                " '#{tgt.username}' at '#{tgt.client_hostname}'" +
                (extra_attributes.empty? ? "" : " with extra attributes #{extra_attributes.inspect}"))
              return tgt
            else
              return nil
            end
          end

          def generate_service_ticket(service, username, tgt, client)
            st = tgt.service_tickets.new
            st.ticket = "ST-" + Util.random_string
            st.service = service
            st.username = username
            st.ticket_granting_ticket = tgt
            st.client_hostname = client
            if st.save
              $LOG.debug("Generated service ticket '#{st.ticket}' for service '#{st.service}'" +
                " for user '#{st.username}' at '#{st.client_hostname}'")
              return st
            else
              return nil
            end
          end

          def generate_proxy_ticket(target_service, pgt, client)
            # 3.2 (proxy ticket)
            pt = ProxyTicket.new
            pt.ticket = "PT-" + String.random
            pt.service = target_service
            pt.username = pgt.service_ticket.username
            pt.granted_by_pgt_id = pgt.id
            pt.granted_by_tgt_id = pgt.service_ticket.granted_by_tgt_id
            pt.client_hostname = @env['HTTP_X_FORWARDED_FOR'] || @env['REMOTE_HOST'] || @env['REMOTE_ADDR']
            pt.save!
            $LOG.debug("Generated proxy ticket '#{pt.ticket}' for target service '#{pt.service}'" +
              " for user '#{pt.username}' at '#{pt.client_hostname}' using proxy-granting" +
              " ticket '#{pgt.ticket}'")
            pt
          end

          def generate_proxy_granting_ticket(pgt_url, st, client)
            uri = URI.parse(pgt_url)
            https = Net::HTTP.new(uri.host,uri.port)
            https.use_ssl = true
        
            # Here's what's going on here:
            #
            #   1. We generate a ProxyGrantingTicket (but don't store it in the database just yet)
            #   2. Deposit the PGT and it's associated IOU at the proxy callback URL.
            #   3. If the proxy callback URL responds with HTTP code 200, store the PGT and return it;
            #      otherwise don't save it and return nothing.
            #
            https.start do |conn|
              path = uri.path.empty? ? '/' : uri.path
              path += '?' + uri.query unless (uri.query.nil? || uri.query.empty?)
              
              pgt = ProxyGrantingTicket.new
              pgt.ticket = "PGT-" + String.random(60)
              pgt.iou = "PGTIOU-" + String.random(57)
              pgt.service_ticket_id = st.id
              pgt.client_hostname = @env['HTTP_X_FORWARDED_FOR'] || @env['REMOTE_HOST'] || @env['REMOTE_ADDR']
        
              # FIXME: The CAS protocol spec says to use 'pgt' as the parameter, but in practice
              #         the JA-SIG and Yale server implementations use pgtId. We'll go with the
              #         in-practice standard.
              path += (uri.query.nil? || uri.query.empty? ? '?' : '&') + "pgtId=#{pgt.ticket}&pgtIou=#{pgt.iou}"
        
              response = conn.request_get(path)
              # TODO: follow redirects... 2.5.4 says that redirects MAY be followed
              # NOTE: The following response codes are valid according to the JA-SIG implementation even without following redirects
              
              if %w(200 202 301 302 304).include?(response.code)
                # 3.4 (proxy-granting ticket IOU)
                pgt.save!
                $LOG.debug "PGT generated for pgt_url '#{pgt_url}': #{pgt.inspect}"
                pgt
              else
                $LOG.warn "PGT callback server responded with a bad result code '#{response.code}'. PGT will not be stored."
                nil
              end
            end
          end
        end
      end
    end
  end
end

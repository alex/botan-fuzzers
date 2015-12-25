
#ifndef BOTAN_FUZZER_ENTROPY_POINTS_H__
#define BOTAN_FUZZER_ENTROPY_POINTS_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/credentials_manager.h>
#include <botan/system_rng.h>
#include <cstdint>

using namespace Botan;

inline int fuzz_cert(const uint8_t in[], size_t len)
   {
   try
      {
      DataSource_Memory input(in, len);
      X509_Certificate cert(input);
      }
   catch(Botan::Exception&) {}

   return 0;
   }

inline int fuzz_crl(const uint8_t in[], size_t len)
   {
   try
      {
      DataSource_Memory input(in, len);
      X509_Certificate cert(input);
      }
   catch(Botan::Exception&) {}

   return 0;
   }

class Fuzzer_Creds : public Credentials_Manager
   {
   public:
      void verify_certificate_chain(const std::string& type,
                                    const std::string& purported_hostname,
                                    const std::vector<X509_Certificate>& cert_chain) override
         {
         try
            {
            Credentials_Manager::verify_certificate_chain(type,
                                                          purported_hostname,
                                                          cert_chain);
            }
         catch(std::exception& e) {}
         }

      // TODO: add certificates

      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }
      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }
      SymmetricKey psk(const std::string&, const std::string&, const std::string&) override
         {
         return SymmetricKey("AABBCCDDEEFF00112233445566778899");
         }
   };

inline int fuzz_tls_client(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return 0;

   auto dev_null = [](const byte[], size_t) {};

   auto ignore_alerts = [](TLS::Alert, const byte[], size_t) {};
   auto ignore_hs = [](const TLS::Session&) { return true; };

   Botan::System_RNG rng;
   TLS::Session_Manager_Noop session_manager;
   TLS::Policy policy;
   TLS::Protocol_Version client_offer = TLS::Protocol_Version::TLS_V12;
   TLS::Server_Information info("server.name", 443);
   const std::vector<std::string> protocols_to_offer = { "fuzz/1.0", "http/1.1", "bunny/1.21.3" };
   Fuzzer_Creds creds;

   TLS::Client client(dev_null,
                      dev_null,
                      ignore_alerts,
                      ignore_hs,
                      session_manager,
                      creds,
                      policy,
                      rng,
                      info,
                      client_offer,
                      protocols_to_offer);

   try
      {
      while(len > 0)
         {
         const size_t write_len = in[0];
         const size_t left = len - 1;

         const size_t consumed = std::min(left, write_len);

         client.received_data(in + 1, consumed);

         in += consumed + 1;
         len -= consumed + 1;
         }
      }
   catch(std::exception& e)
      {
      return 0;
      }
   return 0;
   }

inline int fuzz_tls_server(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return 0;

   auto dev_null = [](const byte[], size_t) {};

   auto ignore_alerts = [](TLS::Alert, const byte[], size_t) {};
   auto ignore_hs = [](const TLS::Session&) { return true; };

   Botan::System_RNG rng;
   TLS::Session_Manager_Noop session_manager;
   TLS::Policy policy;
   TLS::Protocol_Version client_offer = TLS::Protocol_Version::TLS_V12;
   TLS::Server_Information info("server.name", 443);
   Fuzzer_Creds creds;

   auto next_proto_fn = [](const std::vector<std::string>& protos) -> std::string {
      if(protos.size() > 1)
         return protos[0];
      else
         return "fuzzed";
   };

   const bool is_datagram = (len % 2 == 0);

   TLS::Server server(dev_null,
                      dev_null,
                      ignore_alerts,
                      ignore_hs,
                      session_manager,
                      creds,
                      policy,
                      rng,
                      next_proto_fn,
                      is_datagram);

   try
      {
      while(len > 0)
         {
         const size_t write_len = in[0];
         const size_t left = len - 1;

         const size_t consumed = std::min(left, write_len);

         server.received_data(in + 1, consumed);

         in += consumed + 1;
         len -= consumed + 1;
         }
      }
   catch(std::exception& e)
      {
      return 0;
      }
   return 0;
   }

#endif

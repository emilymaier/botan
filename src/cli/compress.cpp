/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_COMPRESSION)

#include <botan/compression.h>
#include <fstream>

namespace {

void do_compress(Transform& comp, std::ifstream& in, std::ostream& out)
   {
   secure_vector<byte> buf;

   comp.start();

   while(in.good())
      {
      buf.resize(64*1024);
      in.read(reinterpret_cast<char*>(&buf[0]), buf.size());
      buf.resize(in.gcount());

      comp.update(buf);

      out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
      }

   buf.clear();
   comp.finish(buf);
   out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
   }

int compress(const std::vector<std::string> &args)
   {
   if(args.size() < 2 || args.size() > 4)
      {
      std::cout << "Usage: " << args[0] << " input [type] [level]" << std::endl;
      return 1;
      }

   const std::string in_file = args[1];
   std::ifstream in(in_file);

   if(!in.good())
      {
      std::cout << "Couldn't read " << in_file << std::endl;
      return 1;
      }

   const std::string suffix = args.size() >= 3 ? args[2] : "gz";
   const size_t level = args.size() >= 4 ? to_u32bit(args[3]) : 9;

   std::unique_ptr<Transform> compress(make_compressor(suffix, level));

   if(!compress)
      {
      std::cout << suffix << " compression not supported" << std::endl;
      return 1;
      }

   const std::string out_file = in_file + "." + suffix;
   std::ofstream out(out_file);

   do_compress(*compress, in, out);

   return 0;
   }

void parse_extension(const std::string& in_file,
                     std::string& out_file,
                     std::string& suffix)
   {
   auto last_dot = in_file.find_last_of('.');
   if(last_dot == std::string::npos || last_dot == 0)
      throw std::runtime_error("No extension detected in filename '" + in_file + "'");

   out_file = in_file.substr(0, last_dot);
   suffix = in_file.substr(last_dot+1, std::string::npos);
   }

int uncompress(const std::vector<std::string> &args)
   {
   if(args.size() != 2)
      {
      std::cout << "Usage: " << args[0] << " <file>" << std::endl;
      return 1;
      }

   const std::string in_file = args[1];
   std::ifstream in(in_file);

   if(!in.good())
      {
      std::cout << "Couldn't read '" << args[1] << "'" << std::endl;
      return 1;
      }

   std::string out_file, suffix;
   parse_extension(in_file, out_file, suffix);

   std::ofstream out(out_file);

   std::unique_ptr<Transform> decompress(make_decompressor(suffix));

   if(!decompress)
      {
      std::cout << suffix << " decompression not supported" << std::endl;
      return 1;
      }

   do_compress(*decompress, in, out);

   return 0;
   }

REGISTER_APP(compress);
REGISTER_APP(uncompress);

}

#endif // BOTAN_HAS_COMPRESSION

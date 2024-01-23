
require 'fileutils'

copmilers = ["iar","armgcc"]
targets = ["debug","release"]
cores = ["cm7f","cm33f"]

cwd = Dir.pwd
dest_dir = cwd + "/libs/"
cwd += "/libs/"

for core in cores
    if core == "cm7f"
        new_cwd = cwd + "evkcmimxrt1060"
    elsif core == "cm33f"
        new_cwd = cwd + "lpcxpresso55s69"
    end
    for c in copmilers
        for t in targets
            new_dir = dest_dir + core + '/' + c + '/' + t + '/'
            files = Dir["#{new_cwd}/**/#{c}/#{t}/*.a"]
            for f in files
                puts "copying #{f} into #{new_dir}"
                FileUtils.cp(f, new_dir)
            end
        end
    end
end


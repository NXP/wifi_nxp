
require 'fileutils'
require 'optparse'

toolchains = []
targets = []
cores = []

cwd = Dir.pwd
cwd += "/libs/"

Dir.chdir "../../bin/generator/batch_v3"
puts Dir.pwd

$project_names = ""
$core_names = "all"
$tool_names = "all"
$target_names = "all"
$generate = false

opt_parser = OptionParser.new do | opts |
opts.on("-p", "--project [String value]", String, "Name of project to be generated and built separated with ',' without space [libmaestro_cci,libmaestro_streamer,libmaestro_utils,...]") do | value |
    $project_names = value
    # p value
end

opts.on("-g", "--generate", "Generate project files with SDK generator") do | value |
    $generate = value
    # p value
end

opts.on("-c", "--core [String value]", String, "Name of core to be generated and built [cm7f,cm33f]") do | value |
    $core_names = value
    # p value
end

opts.on("-t", "--toolchain [String value]", String, "Name of toolchain to be generated and built [iar,armgcc]") do | value |
    $tool_names = value
    # p value
end

opts.on("-d", "--target [String value]", String, "Targets to be generated and built [debug,release]") do | value |
    $target_names = value
    # p value
end

opts.on_tail("-h", "--help", "Show help for console usage") do
    puts opts
exit 0
end
end
opt_parser.parse!

# puts $project_names
# puts $core_names

$CMD = "ruby all_evkcmimxrt1060.rb -a sigma_agent"
# $CMD2 = "ruby all_lpcxpresso55s69.rb -a maestro"

# # if not specified a core, build all
# if $core_names == ""
#     $core_names = "all"
# end

if $project_names != ""
    $CMD += " -p #{$project_names}"
end
if $tool_names != ""
    if $tool_names["iar"] || $tool_names["all"]
        toolchains << "iar"
    end
    if $tool_names["armgcc"] || $tool_names["all"]
        toolchains << "armgcc"
    end
    if $tool_names == "all"
        $tool_names = "iar,armgcc"
    end
    $CMD += " -t #{$tool_names}"

end
if $target_names != ""
    if $target_names["debug"] || $target_names["all"]
        targets << "debug"
    end
    if $target_names["release"] || $target_names["all"]
        targets << "release"
    end
end
# puts $CMD
if $core_names != ""
    if $core_names["cm7f"] || $core_names["all"]
        cores << "cm7f"
        if $generate
            system("#{$CMD}")
        end
    end
    if $core_names["cm33f"] || $core_names["all"]
        cores << "cm33f"
        $CMD.sub!("evkcmimxrt1060","lpcxpresso55s69")
        $CMD += " --core_id cm33_core0"
        if $generate
            system("#{$CMD}")
        end
    end
end

Dir.chdir "#{cwd}"
# puts Dir.pwd

def build_iar(f,t)
    log = f.dup
    log.sub!(/(iar).*(ewp)/, "iar/log_#{t}.txt")
    puts "building #{f} #{t}"
    output=`IarBuild.exe #{f} -make "#{t}" -parallel 4 > #{log}` ;  result=$?.success?
    if result == false
        puts "build error"
    else
        puts "build ok"
    end
end

def build_gcc(f,t)
    dirname = File.dirname("#{f}") + '/'
    puts "building #{dirname}#{t}"
    Dir.chdir "#{dirname}"
    output=`#{f}` ;  result=$?.success?
    if result == false
        puts "build error"
    else
        puts "build ok"
    end
end

for core in cores
    if core == "cm7f"
        new_cwd = cwd + "evkcmimxrt1060"
    elsif core == "cm33f"
        new_cwd = cwd + "lpcxpresso55s69"
    end

    if toolchains.include? "iar"
        for t in targets
            files = Dir["#{new_cwd}/**/*.ewp"]
            for f in files
                if $project_names != ""
                    for proj in $project_names.split(",")
                        # build just projects defined on command line
                        if f.include?proj
                            build_iar(f,t)
                        end
                    end
                else
                    build_iar(f,t)
                end
            end
        end
    end

    if toolchains.include? "armgcc"
        for t in targets
            files = Dir["#{new_cwd}/**/build_#{t}.sh"]
            for f in files
                if $project_names != ""
                    for proj in $project_names.split(",")
                        # build just projects defined on command line
                        if f.include?proj
                            build_gcc(f,t)
                        end
                    end
                else
                    build_gcc(f,t)
                end
            end
        end
    end
end

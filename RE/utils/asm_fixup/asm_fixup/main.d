import std.stdio;
import std.getopt;
import std.file;
import std.string;
import std.regex;
import core.sys.windows.windows;
import std.conv;
import std.algorithm.sorting;
import std.path;

int get_key()
{
	int result=0;
	HANDLE hcon;
	hcon=GetStdHandle(STD_INPUT_HANDLE);
	if(hcon!=INVALID_HANDLE_VALUE){
		DWORD oldstate;
        GetConsoleMode(hcon,&oldstate);
        SetConsoleMode(hcon,0);
		while(true){
			INPUT_RECORD rec;
			DWORD count=0;
			if(ReadConsoleInput(hcon,&rec,1,&count)){
				if(count==1){
					if(rec.EventType==KEY_EVENT && rec.Event.KeyEvent.bKeyDown){
						result=cast(int)rec.Event.KeyEvent.wVirtualKeyCode;
						break;
					}
				}else
					break;
			}else{
				break;
			}
		}
		SetConsoleMode(hcon,oldstate);
	}
	return result;
}

void parse_file(string fname,string output)
{
	string[] lines=readText(fname).splitLines();
	string[] list1;
	string[] list2;
	string[] list3;
	auto rx=regex("Unnamed_\\w+_\\w+");
	foreach(s;lines){
		int x=indexOf(s,"Unnamed_");
		string match;
		if(x>=0){
			auto m=matchFirst(s,rx);
			if(!m.empty){
				match=m[0];
			}
		}
		if(match.length>0){
			if(x==0){
				list1~=match;
			}else if(x>0){
				bool found=false;
				foreach(z;list2){
					if(z==match){
						found=true;
						break;
					}
				}
				if(!found)
					list2~=match;				
			}
		}
	}
	//list1= labels
	//list2= operands
	//list3= need fix
	foreach(s;list2){
		bool found=false;
		foreach(s2;list1){
			if(s==s2){
				found=true;
				break;
			}
		}
		if(!found){
			writeln("not found:"~s);
			list3~=s;
		}
	}
	rx=regex("Unnamed_\\w+_(\\w+)");
	struct INSERT{
		string label;
		int index;
	}
	INSERT[] insert;
	foreach(s;list3){
		auto m=matchFirst(s,rx);
		if(m.empty){
			writeln("empty");
		}
		string tmp=m[1];
		int val=tmp.to!int(16);
		val+=0x401000;
		tmp=format("%08X",val);
		foreach(i,line;lines){
			int x=indexOf(line,tmp);
			if(x>=0){
				INSERT ins;
				ins.label=s;
				ins.index=i;
				insert~=ins;
				writeln("adding:"~s);
				break;
			}			
		}
	}
	sort!("a.index<b.index")(insert);
	string[] result;
	int index=0;
	foreach(ins;insert){
		writeln(ins.index," ",ins.label);
		int i;
		for(i=index;i<ins.index;i++){
			if(i>=lines.length)
				break;
			result~=lines[i];
			index++;
		}
		result~=ins.label~":";
	}
	for(int i=index;i<lines.length;i++){
		result~=lines[i];
	}
	string tmp=dirName(fname);
	tmp=buildNormalizedPath(tmp,output);
	auto f=File(tmp,"wb");
	foreach(s;result){
		f.writeln(s);
	}
	f.close();
}
void fix_exports()
{
	string asm_file="c:\\DEV\\MSVC_Projects\\disasm_exe\\VS2005\\pe_disasm\\CRACKED_MOTO.asm";
	string out_file="c:\\DEV\\MSVC_Projects\\disasm_exe\\VS2005\\pe_disasm\\fixed.asm";
	string export_file="c:\\DEV\\MSVC_Projects\\disasm_exe\\VS2005\\pe_disasm\\libs\\export_list.txt";
	if(!exists(asm_file))
		return;
	if(!exists(export_file))
		return;
	string[] asm_lines=readText(asm_file).splitLines();
	string[] exp_lines=readText(export_file).splitLines();
	string[] def_list;
	auto re=regex("(extern )(\\S+)(.+)");
	auto re2=regex("(\\S+)@");
	int section_start=0;
	foreach(index,line;asm_lines){
		auto m=matchFirst(line,re);		
		if(!m.empty){
			string sym=m[2];
			//writeln(sym);
			int found=false;
			foreach(e;exp_lines){
				auto m2=matchFirst(e,re2);
				string tmp;
				if(m2.empty){
					tmp=e;
				}
				else
					tmp=m2[1];
				if(tmp.length==0){
					writeln("error:empty string");
					continue;
				}
				if(tmp[0]=='_')
					tmp=tmp[1..$];
				
				if(tmp==sym){
					//writeln(e);
					asm_lines[index]=m[1]~e~m[3];
					def_list~="%define imp_"~sym~" "~e;
					found=true;
					break;
				}
			}
			if(!found){
				writeln("not found lookup for:"~sym);
			}
		}
		if(indexOf(line,"SECTION")>=0){
			section_start=index;
			break;
		}
	}
	//return;
	auto f=File(out_file,"wb");
	foreach(index,s;asm_lines){
		if(index==section_start){
			foreach(t;def_list){
				f.writeln(t);
			}
		}
		f.writeln(s);
	}
	f.close();
	
}
string remove_label(string str)
{
	string result=str;
	while(true){
		int pos=indexOf(result,"?_");
		if(pos>=0){
			string tmp=result[0..pos];
			int i;
			for(i=pos;i<result.length;i++){
				char a=result[i];
				if(a=='?' || a=='_' || (a>='0' && a<='9')){
				}else{
					break;
				}
			}
			tmp~=result[i..$];
			result=tmp;
		}else{
			break;
		}
	}
	return result;
}
string remove_llabel(string str)
{
	if(str.length==0)
		return str;
	if(str[0]=='?'){
		string tmp;
		int i;
		for(i=0;i<str.length;i++){
			char a=str[i];
			tmp~=' ';
			if(a==':'){
				i++;
				break;
			}
		}
		for( ;i<str.length;i++){
			tmp~=str[i];
		}
		return tmp;
	}
	return str;
}
void check_files()
{
	string fname1="c:\\DEV\\MSVC_Projects\\disasm_exe\\VS2005\\pe_disasm\\CRACKED_MOTO.asm";
	string fname2="c:\\DEV\\MSVC_Projects\\disasm_exe\\VS2005\\pe_disasm\\fixed2.asm";
	if(!exists(fname1))
		return;
	if(!exists(fname2))
		return;
	string fs;
	fs=cast(string)read(fname1);
	string[] f1=fs.splitLines();
	fs=cast(string)read(fname2);
	string[] f2=fs.splitLines();
	foreach(index,s1;f1){
		if(index<500)
			continue;
		int pos=indexOf(s1,";");
		if(pos<56)
			continue;
		string tmp=s1[pos..$];
		int i=index;
		i-=3000;
		if(i<0)
			i=0;
		int max=i+10000;
		if(max>f2.length)
			max=f2.length;
		bool found=false;
		int findex=0;
		for( ;i<max;i++){
			string s2=f2[i];
			findex=indexOf(s2,tmp);
			if(findex>=0){
				string x=s2[0..findex];
				string y=s1[0..pos];
				x=remove_llabel(x);
				y=remove_llabel(y);
				x=remove_label(x);
				y=remove_label(y);
				if(x==y){
					found=true;
					break;
				}
			}
		}
		if(!found){
			int len=s1.length;
			if(len>78)
				len=78;
			writeln(s1[0..len]);
		}
	}
}

int main(string[] args)
{
	string fname;
	string outfile;
	
	check_files();
	writeln("done");
	get_key();
	return 0;
	
	getopt(args,
		"fin", &fname,
		"out", &outfile);

	if(exists(fname)){
		parse_file(fname,outfile);
	}
	writeln("done");
	get_key();
    return 0;
}

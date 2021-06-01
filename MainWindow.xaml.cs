using MemUtil;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace UnitySceneExplorer
{

	public static class Game
	{
		public static Process proc;
		public static bool is64bit;
		private static Dictionary<string, Scene> sceneDict;
		private static Dictionary<string, GameObject> objDict;
		private static Dictionary<string, ObjectComponent> compDict;

		internal static Dictionary<string, GameObject> ObjDict { get => objDict; set => objDict = value; }
		internal static Dictionary<string, Scene> SceneDict { get => sceneDict; set => sceneDict = value; }
		internal static Dictionary<string, ObjectComponent> CompDict { get => compDict; set => compDict = value; }
	}


	public partial class MainWindow : Window
	{

		private Process game;
		private SigScanTarget SceneManagerTarget;
		private SignatureScanner Scanner;
		private IntPtr SceneManager;

		private List<Scene> scenes;
		private static TextBlock objBlock;

		public MainWindow()
		{
			InitializeComponent();
			objBlock = objTextBlock;
			Game.ObjDict = new Dictionary<string, GameObject>();
			Game.SceneDict = new Dictionary<string, Scene>();
			Game.CompDict = new Dictionary<string, ObjectComponent>();
			Scan();
			

		}

		private void Scan()
		{
			var startTime = System.DateTime.Now;
			string processName = processBox.Text;
			if (processName.Contains(".exe")) processName = processName.Replace(".exe", "");
			List<Process> processList = Process.GetProcesses().ToList().FindAll(x => x.ProcessName.Contains(processName));
			if (processList.Count == 0) return;
			game = processList[0];
			Game.proc = processList[0];
			Game.is64bit = Game.proc.Is64Bit();

			if (Game.is64bit)
			{
				SceneManagerTarget = new SigScanTarget();
				SceneManagerTarget.AddSignature(3, "48 8B 0D ?? ?? ?? ?? 48 8D 55 ?? 89 45 ?? 0F");
				SceneManagerTarget.AddSignature(3, "4C 8B 3D ?? ?? ?? ?? 4C 89 7C 24");
				SceneManagerTarget.OnFound = (f_proc, f_scanner, f_ptr, f_o, f_sig) =>
				{
					return IntPtr.Add(f_ptr + 4, game.ReadValue<int>(f_ptr));
				};


			}
			else
			{
				SceneManagerTarget = new SigScanTarget();
				SceneManagerTarget.AddSignature(1, "A1 ?? ?? ?? ?? 53 33 DB 89 45");

				SceneManagerTarget.OnFound = (f_proc, f_scanner, f_ptr, f_o, f_sig) =>
				{
					if (!f_proc.ReadPointer(f_ptr, out f_ptr)) return IntPtr.Zero;

					return f_ptr;
				};
			}
			var UnityPlayer = game.ModulesWow64Safe().FirstOrDefault(m => m.ModuleName == "UnityPlayer.dll");
			if (UnityPlayer == null) return;
			Scanner = new SignatureScanner(game, UnityPlayer.BaseAddress, UnityPlayer.ModuleMemorySize);
			if ((SceneManager = Scanner.Scan(SceneManagerTarget)) != IntPtr.Zero)
			{
				Debug.WriteLine("Found SceneManager: 0x" + SceneManager.ToString("X"));
			}
			Game.ObjDict.Clear();
			Game.SceneDict.Clear();
			Game.CompDict.Clear();

			scenes = new List<Scene>();
			new DeepPointer(SceneManager, (Game.is64bit ? 0x70 : 0x40)).DerefOffsets(game, out IntPtr dontDestroyScenePtr);
			scenes.Add(new Scene(game, dontDestroyScenePtr));

			new DeepPointer(SceneManager, Game.is64bit ? 0x18 : 0x10).Deref<int>(game, out int numLoadedScenes);
			for (int i = 0; i < numLoadedScenes; i++)
			{
				new DeepPointer(SceneManager, 0x8, i * (Game.is64bit ? 0x8 : 0x4), 0x0).DerefOffsets(game, out IntPtr scenePtr);
				Debug.WriteLine(scenePtr.ToString("X16"));
				scenes.Add(new Scene(game, scenePtr));
			}
			

			TreeView.Items.Clear();
			List<MenuItem> sceneItems = new List<MenuItem>();
			foreach (Scene scene in scenes)
			{
				TreeView.Items.Add(scene.GetTreeView());
			}
			statusTextBlock.Text = "Found " + Game.SceneDict.Count + " scenes, " + Game.ObjDict.Count + " GameObjects, " + Game.CompDict.Count + " components in " + (System.DateTime.Now - startTime);
		}

		private void btn_Scan_Click(object sender, RoutedEventArgs e)
		{
			Scan();
		}

		public static void gameObject_selected(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine("game obj selected");
			TreeViewItem item = sender as TreeViewItem;
			objBlock.Text = item.Header.ToString();
			GameObject obj = Game.ObjDict[(item.Header.ToString().Substring(1, 16))];
			if(obj.components.Count > 0)
			{
				objBlock.Text += "\n\nComponents";
				foreach (ObjectComponent component in obj.components)
				{
					objBlock.Text += "\n" + component.ToString();
				}
			}
			e.Handled = true;
		}

		public static void scene_selected(object sender, RoutedEventArgs e)
		{
			Debug.WriteLine("scene selected");
			TreeViewItem item = sender as TreeViewItem;
			objBlock.Text = item.Header.ToString();
			e.Handled = true;
		}
	}


	class Scene
	{
		Process game;
		public IntPtr adr;
		public string name;
		public List<GameObject> rootObjects;

		public Scene(Process game, IntPtr ptr)
		{
			this.game = game;
			this.adr = ptr;
			this.name = GetName();
			this.rootObjects = GetRootObjects();
			Game.SceneDict.Add(this.adr.ToString("X16"), this);
		}

		string GetName()
		{
			return new DeepPointer(this.adr + (Game.is64bit ? 0x10 : 0xC), 0x0).DerefString(game, 250);
		}

		List<GameObject> GetRootObjects()
		{
			List<IntPtr> objects = new List<IntPtr>();
			new DeepPointer(this.adr + (Game.is64bit ? 0xB8 : 0x8C), 0x0).DerefOffsets(game, out IntPtr objectPtr);
			new DeepPointer(this.adr + (Game.is64bit ? 0xB0 : 0x88), 0x0).DerefOffsets(game, out IntPtr lastObjectPtr);

			while (objectPtr != lastObjectPtr && objectPtr != IntPtr.Zero)
			{
				new DeepPointer(objectPtr + (Game.is64bit ? 0x8 : 0x4), 0x0).DerefOffsets(game, out objectPtr);
				objects.Add(objectPtr);
			}
			new DeepPointer(objectPtr + (Game.is64bit ? 0x8 : 0x4), 0x0).DerefOffsets(game, out objectPtr);
			objects.Add(objectPtr);

			List<GameObject> output = new List<GameObject>();
			foreach (IntPtr oPtr in objects)
			{
				new DeepPointer(oPtr, (Game.is64bit ? 0x10 : 0x8), (Game.is64bit ? 0x30 : 0x1C), 0x0).DerefOffsets(game, out IntPtr goPtr);
				output.Add(new GameObject(game, goPtr));
			}

			return output;
		}

		public string ToString(bool includeObjects)
		{
			string output = "";
			output += "[" + this.adr.ToString("X16") + "] Scene: \"" + this.name + "\"\n";
			if (!includeObjects) return output;

			foreach (GameObject gameObject in rootObjects)
			{
				output += gameObject.ToString(true, 1)+"\n";
			}
			return output;
		}

		public override string ToString()
		{
			return this.ToString(false);
		}

		public TreeViewItem GetTreeView()
		{
			TreeViewItem output = new TreeViewItem() { Header = "[" + this.adr.ToString("X16") + "] " + this.name };
			output.Selected += MainWindow.scene_selected;
			foreach (GameObject rootObject in this.rootObjects)
			{
				output.Items.Add(rootObject.GetTreeView());
			}


			return output;
		}

	}


	class GameObject
	{
		Process game;
		public IntPtr adr;
		public int childCount;
		public string name;
		public List<GameObject> children;
		public List<ObjectComponent> components;

		public GameObject(Process game, IntPtr ptr)
		{
			this.game = game;
			this.adr = ptr;
			this.name = GetName();
			this.childCount = GetChildren(out this.children);
			this.components = GetComponents();
			Game.ObjDict.Add(this.adr.ToString("X16"), this);
		}

		string GetName()
		{
			return new DeepPointer(this.adr + (Game.is64bit ? 0x60 : 0x3C), 0x0).DerefString(game, 250);
		}

		int GetChildren(out List<GameObject> childList)
		{
			childList = new List<GameObject>();
			List<IntPtr> output = new List<IntPtr>();
			new DeepPointer(this.adr + (Game.is64bit ? 0x30 : 0x1C), (Game.is64bit ? 0x8 : 0x4), 0x0).DerefOffsets(game, out IntPtr transform);
			game.ReadValue<int>(transform + (Game.is64bit ? 0x80 : 0x58), out int childCount);
			for (int i = 0; i < childCount; i++)
			{
				new DeepPointer(transform + (Game.is64bit ? 0x70 : 0x50), (Game.is64bit ? 0x8 : 0x4) * i, (Game.is64bit ? 0x30 : 0x1C), 0x0).DerefOffsets(game, out IntPtr childPtr);
				childList.Add(new GameObject(game, childPtr));
			}
			return childCount;
		}

		List<ObjectComponent> GetComponents()
		{
			List<ObjectComponent> output = new List<ObjectComponent>();
			int numComponents = game.ReadValue<int>(this.adr + (Game.is64bit ? 0x40 : 0x24));
			for (var i = 0; i < numComponents; i++)
			{
				new DeepPointer(this.adr + (Game.is64bit ? 0x30 : 0x1C), (Game.is64bit ? 0x8 : 0x4) + i * (Game.is64bit ? 0x10 : 0x8), 0x0).DerefOffsets(game, out IntPtr compPtr);
				ObjectComponent component = new ObjectComponent(game, compPtr);
				if (i == 0) component.name = "Transform";
				output.Add(component);
			}


			return output;
		}



		public string ToString(bool recursive, int depth = 0)
		{
			string output = "";
			for (var i = 0; i < depth; i++)
				output += "----";

			string prefix = output;

			output += "[" + this.adr.ToString("X16") + "] \"" + this.name + "\""; ;
			output += " Components:";
			foreach (ObjectComponent component in this.components)
			{
				output += " " + component.ToString();
			}

			if (recursive)
			{
				foreach (GameObject child in this.children)
				{
					output += "\n" + child.ToString(true, depth + 1);
				}
			}
			return output;

		}

		public override string ToString()
		{
			return this.ToString(false);
		}

		public TreeViewItem GetTreeView()
		{
			TreeViewItem output = new TreeViewItem() { Header = "[" + this.adr.ToString("X16") + "] " + this.name };
			output.Selected += MainWindow.gameObject_selected;
			foreach (GameObject childObject in children)
			{
				output.Items.Add(childObject.GetTreeView());
			}

			return output;
		}
	}

	class ObjectComponent
	{
		Process game;
		public IntPtr adr;
		public string name;

		public ObjectComponent(Process game, IntPtr adr)
		{
			this.adr = adr;
			this.game = game;
			this.name = GetName();
			Game.CompDict.Add(this.adr.ToString("X16"), this);
		}

		string GetName()
		{
			string output = "???";
			if (new DeepPointer(this.adr+(Game.is64bit ? 0x28 : 0x18), 0x0, 0x0, (Game.is64bit ? 0x48 : 0x2C), 0x0).DerefOffsets(game, out IntPtr namePtr)) output = game.ReadString(namePtr, 250);
			return output;
		}

		public override string ToString()
		{
			return "[" + this.adr.ToString("X16") + "] " + this.name;
		}
	}

	public class MenuItem
	{
		public MenuItem()
		{
			this.Items = new ObservableCollection<MenuItem>();
		}

		public string Title { get; set; }

		public ObservableCollection<MenuItem> Items { get; set; }
	}


}
